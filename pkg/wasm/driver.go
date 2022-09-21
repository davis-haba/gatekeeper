package wasm

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"

	wasmtime "github.com/bytecodealliance/wasmtime-go"
	constraints2 "github.com/open-policy-agent/frameworks/constraint/pkg/apis/constraints"
	"github.com/open-policy-agent/frameworks/constraint/pkg/client/drivers"
	"github.com/open-policy-agent/frameworks/constraint/pkg/core/templates"
	"github.com/open-policy-agent/frameworks/constraint/pkg/types"
	target2 "github.com/open-policy-agent/gatekeeper/pkg/target"
	"github.com/open-policy-agent/opa/storage"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

var root = flag.String("wasm-root", "~", "the root directory to search for WASM, defaults to homedir")

func NewDriver() *Driver {
	runPython, err := bootStrapPython()
	if err != nil {
		panic(err)
	}
	return &Driver{
		pythonModules: make(map[string]string),
		runPython:     runPython,
	}
}

type Driver struct {
	pythonModules map[string]string
	runPython     func(string, string, string) (string, error)
}

type WasmDecision struct {
	Decision   string
	Name       string
	Constraint *unstructured.Unstructured
}

var _ drivers.Driver = &Driver{}

func (d *Driver) AddTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {

	if len(ct.Spec.Targets) == 0 {
		return nil
	}

	pythonCode := ct.Spec.Targets[0].Rego //Python

	if pythonCode == "" {
		return nil
	}
	/// TODO: let's pretend this is just a string for now
	/// TODO: mutex
	d.pythonModules[ct.Name] = pythonCode
	return nil
}

func (d *Driver) RemoveTemplate(ctx context.Context, ct *templates.ConstraintTemplate) error {
	delete(d.pythonModules, ct.Name)

	return nil
}

func (d *Driver) AddConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	pythonModuleName := strings.ToLower(constraint.GetKind())

	_, found := d.pythonModules[pythonModuleName]
	if !found {
		return fmt.Errorf("no wasmModuleName with name: %q", pythonModuleName)
	}

	return nil
}

func (d *Driver) RemoveConstraint(ctx context.Context, constraint *unstructured.Unstructured) error {
	return nil
}

func (d *Driver) AddData(ctx context.Context, target string, path storage.Path, data interface{}) error {
	return nil
}

func (d *Driver) RemoveData(ctx context.Context, target string, path storage.Path) error {
	return nil
}

// bootStrapPython loads a python intepreter into a WASM VM, then returns a handle
// that allows the user to execute the passed python code.
func bootStrapPython() (func(string, string, string) (string, error), error) {
	base := ""
	if *root == "~" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		base = home
	} else {
		base = *root
	}
	root := path.Join(base, "hackathon/gatekeeper/wasm/Python-3.11.0rc2-wasm32-wasi-16")
	src := path.Join(root, "python.wasm")

	wasm, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}

	engine := wasmtime.NewEngine()
	module, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return nil, err
	}

	linker := wasmtime.NewLinker(engine)
	if err := linker.DefineWasi(); err != nil {
		return nil, err
	}

	store := wasmtime.NewStore(engine)
	instance, err := linker.Instantiate(store, module)
	if err != nil {
		return nil, err
	}

	if err := linker.DefineInstance(store, "python", instance); err != nil {
		return nil, err
	}

	return func(code, data, params string) (string, error) {
		guestRead, _, err := os.Pipe()
		if err != nil {
			return "", err
		}
		defer guestRead.Close()

		guestReadHandle := path.Join("/proc", fmt.Sprintf("%d", syscall.Getpid()), "fd", fmt.Sprintf("%d", guestRead.Fd()))

		hostRead, guestWrite, err := os.Pipe()
		if err != nil {
			return "", err
		}
		defer hostRead.Close()
		defer guestWrite.Close()

		guestWriteHandle := path.Join("/proc", fmt.Sprintf("%d", syscall.Getpid()), "fd", fmt.Sprintf("%d", guestWrite.Fd()))

		// wasmtime closes file handles when the destructor is called (via golang GC)... it's not clear whether replacing
		// the wasiConfig is sufficient to trigger this condition, so this may be an FD leak.
		wasiConfig := wasmtime.NewWasiConfig()
		if err := wasiConfig.SetStdinFile(guestReadHandle); err != nil {
			return "", err
		}
		if err := wasiConfig.SetStdoutFile(guestWriteHandle); err != nil {
			return "", err
		}
		wasiConfig.InheritStderr()
		wasiConfig.SetArgv([]string{`python`, `-c`, code, data, params})
		wasiConfig.PreopenDir(root, "/")

		store.SetWasi(wasiConfig)

		python, err := linker.GetDefault(store, "python")
		if err != nil {
			return "", err
		}

		_, err = python.Call(store)
		if err != nil {
			return "", err
		}

		response, err := readToEnd(guestWrite, hostRead)
		if err != nil {
			return "", err
		}
		return response, nil
	}, nil
}

func (d *Driver) Query(ctx context.Context, target string, constraints []*unstructured.Unstructured, review interface{}, opts ...drivers.QueryOpt) ([]*types.Result, *string, error) {

	gkr := review.(*target2.GkReview)

	obj := &unstructured.Unstructured{
		Object: make(map[string]interface{}),
	}

	err := obj.UnmarshalJSON(gkr.Object.Raw)
	if err != nil {
		return nil, nil, err
	}

	var allDecisions []*WasmDecision
	for _, constraint := range constraints {
		pythonModule, found := d.pythonModules[strings.ToLower(constraint.GetKind())]
		if !found {
			continue
		}

		paramsStruct, _, err := unstructured.NestedFieldNoCopy(constraint.Object, "spec", "parameters")
		if err != nil {
			return nil, nil, err
		}

		params, err := json.Marshal(paramsStruct)
		if err != nil {
			return nil, nil, err
		}

		// pass in object as os.Args[1]
		results, err := d.runPython(pythonModule, string(gkr.Object.Raw), string(params))
		if err != nil {
			return nil, nil, err
		}

		wasmDecision := &WasmDecision{
			Decision:   results,
			Name:       constraint.GetName(),
			Constraint: constraint,
		}

		allDecisions = append(allDecisions, wasmDecision)
	}
	if len(allDecisions) == 0 {
		return nil, nil, nil
	}

	results := make([]*types.Result, len(allDecisions))
	for i, wasmDecision := range allDecisions {
		enforcementAction, found, err := unstructured.NestedString(wasmDecision.Constraint.Object, "spec", "enforcementAction")
		if err != nil {
			return nil, nil, err
		}
		if !found {
			enforcementAction = constraints2.EnforcementActionDeny
		}

		results[i] = &types.Result{
			Metadata: map[string]interface{}{
				"name": wasmDecision.Name,
			},
			Constraint:        wasmDecision.Constraint,
			Msg:               string(wasmDecision.Decision),
			EnforcementAction: enforcementAction,
		}
	}

	return results, nil, nil
}

func (d *Driver) Dump(ctx context.Context) (string, error) {
	//TODO implement me
	panic("implement me")
}

func readToEnd(w io.Writer, b io.Reader) (string, error) {
	data := make([]byte, 256)
	var builder strings.Builder
	extra := 0
	for {
		l, err := b.Read(data)
		if err != nil {
			return "", err
		}
		if l < 0 {
			return "", errors.New("negative reader read")
		}
		builder.Write(data[:l])
		if l < len(data) {
			break
		}
		// add an extra byte in case we reached the exact end of the buffer
		// otherwise the next read blocks indefinitely
		if l == len(data) {
			extra++
			n, err := w.Write([]byte("+"))
			if err != nil {
				return "", err
			}
			if n != 1 {
				return "", errors.New("could not write extra byte")
			}
		}
	}
	val := builder.String()

	return val[:len(val)-extra], nil
}
