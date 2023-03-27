package verify

import (
	"errors"
	"fmt"
	"strings"
)

type PrinterGo struct{}

var _ Printer = PrinterGo{}

// ErrWritingString means there was a problem writing output to the writer
// passed to Print.
var ErrWritingString = errors.New("writing output")

func (p PrinterGo) Print(w StringWriter, r []SuiteResult, verbose bool) error {
	fail := false
	for i := range r {
		err := p.PrintSuite(w, &r[i], verbose)
		if err != nil {
			return err
		}

		if r[i].IsFailure() {
			fail = true
		}
	}

	if fail {
		_, err := w.WriteString("FAIL\n")
		if err != nil {
			return err
		}
	} else {
		_, err := w.WriteString("PASS\n")
		if err != nil {
			return err
		}
	}

	return nil
}

func (p PrinterGo) PrintSuite(w StringWriter, r *SuiteResult, verbose bool) error {
	for i := range r.TestResults {
		err := p.PrintTest(w, &r.TestResults[i], verbose)
		if err != nil {
			return err
		}
	}

	if r.IsFailure() {
		_, err := w.WriteString(fmt.Sprintf("FAIL\t%s\t%v\n", r.Path, r.Runtime))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
		if r.Error != nil {
			_, err = w.WriteString(fmt.Sprintf("  %v\n", r.Error))
			if err != nil {
				return fmt.Errorf("%w: %w", ErrWritingString, err)
			}
		}
	} else {
		_, err := w.WriteString(fmt.Sprintf("ok\t%s\t%v\n", r.Path, r.Runtime))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
	}
	return nil
}

func (p PrinterGo) PrintTest(w StringWriter, r *TestResult, verbose bool) error {
	if verbose {
		if r.Skipped {
			_, err := w.WriteString(fmt.Sprintf("=== SKIP  %s\n", r.Name))
			if err != nil {
				return fmt.Errorf("%w: %w", ErrWritingString, err)
			}
			return nil
		}

		_, err := w.WriteString(fmt.Sprintf("=== RUN   %s\n", r.Name))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
	}

	for i := range r.CaseResults {
		err := p.PrintCase(w, &r.CaseResults[i], verbose)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
	}

	if r.IsFailure() {
		_, err := w.WriteString(fmt.Sprintf("--- FAIL: %s\t(%v)\n", r.Name, r.Runtime))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
		if r.Error != nil {
			_, err = w.WriteString(fmt.Sprintf("  %v\n", r.Error))
			if err != nil {
				return fmt.Errorf("%w: %w", ErrWritingString, err)
			}
		}
	} else if verbose {
		_, err := w.WriteString(fmt.Sprintf("--- PASS: %s\t(%v)\n", r.Name, r.Runtime))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
	}
	return nil
}

func (p PrinterGo) PrintCase(w StringWriter, r *CaseResult, verbose bool) error {
	if verbose {
		if r.Skipped {
			_, err := w.WriteString(fmt.Sprintf("    === SKIP  %s\n", r.Name))
			if err != nil {
				return fmt.Errorf("%w: %w", ErrWritingString, err)
			}
			return nil
		}

		_, err := w.WriteString(fmt.Sprintf("    === RUN   %s\n", r.Name))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
	}

	if r.Error != nil {
		_, err := w.WriteString(fmt.Sprintf("    --- FAIL: %s\t(%v)\n        %v\n", r.Name, r.Runtime, r.Error))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
	} else if verbose {
		_, err := w.WriteString(fmt.Sprintf("    --- PASS: %s\t(%v)\n", r.Name, r.Runtime))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
	}

	if r.Trace != nil {
		prefix := ""
		if verbose {
			// if using verbose to print, let's keep the trace at the same level
			prefix = "    --- "
		}
		_, err := w.WriteString(fmt.Sprintf("%sTRACE: %s\t%s\n", prefix, r.Name, strings.ReplaceAll(*r.Trace, "\n", "\n"+prefix)))
		if err != nil {
			return fmt.Errorf("%w: %w", ErrWritingString, err)
		}
	}

	return nil
}
