package regoservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	rego_templates "github.com/aquasecurity/postee/v2/rego-templates"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/loader"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

var (
	bundledStateMu     sync.Mutex
	bundledStateKey    string
	bundledCompiler    *ast.Compiler
	bundledCompilerErr error
	bundledQueryCache  sync.Map
)

func bundleStateKey() string {
	var b strings.Builder
	b.WriteString(strings.Join(regoTemplates, "\x00"))
	b.WriteByte(0)
	b.WriteString(strings.Join(commonRegoTemplates, "\x00"))
	b.WriteByte(0)
	b.WriteString(bundledSourceFingerprint())
	return b.String()
}

func bundledSourceFingerprint() string {
	h := sha256.New()
	appendSourceFingerprint(h, regoTemplates, rego_templates.EmbeddedTemplates())
	appendSourceFingerprint(h, commonRegoTemplates, rego_templates.EmbeddedCommon())
	return hex.EncodeToString(h.Sum(nil))
}

func appendSourceFingerprint(h hashWriter, paths []string, embedded map[string]string) {
	foundPaths := existingPaths(paths)
	if len(foundPaths) != 0 {
		result, err := loader.All(foundPaths)
		if err != nil {
			fmt.Fprintf(h, "err:%v", err)
			return
		}
		names := make([]string, 0, len(result.Modules))
		for name := range result.Modules {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			h.Write([]byte(name))
			h.Write(result.Modules[name].Raw)
		}
		return
	}

	names := make([]string, 0, len(embedded))
	for name := range embedded {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte(embedded[name]))
	}
}

type hashWriter interface {
	Write([]byte) (int, error)
}

func existingPaths(paths []string) []string {
	foundPaths := make([]string, 0, len(paths))
	for _, path := range paths {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			foundPaths = append(foundPaths, path)
		}
	}
	return foundPaths
}

func getBundledCompiler() (*ast.Compiler, error) {
	bundledStateMu.Lock()
	defer bundledStateMu.Unlock()

	key := bundleStateKey()
	if bundledCompiler != nil && bundledStateKey == key {
		return bundledCompiler, bundledCompilerErr
	}

	bundledStateKey = key
	bundledCompiler = nil
	bundledCompilerErr = nil
	bundledQueryCache = sync.Map{}

	modules, err := loadBundledModules()
	if err != nil {
		bundledCompilerErr = err
		return nil, err
	}

	compiler := ast.NewCompiler().WithCapabilities(bundledCompilerCapabilities())
	compiler.Compile(modules)
	if compiler.Failed() {
		bundledCompilerErr = compiler.Errors
		return nil, bundledCompilerErr
	}

	bundledCompiler = compiler
	return bundledCompiler, nil
}

func loadBundledModules() (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	// Match rego prepare order: template paths first, then common (embedded common overwrites test common.rego).
	if err := loadBundledModulesFromSource(regoTemplates, rego_templates.EmbeddedTemplates(), modules); err != nil {
		return nil, err
	}
	if err := loadBundledModulesFromSource(commonRegoTemplates, rego_templates.EmbeddedCommon(), modules); err != nil {
		return nil, err
	}
	return modules, nil
}

func loadBundledModulesFromSource(paths []string, embedded map[string]string, modules map[string]*ast.Module) error {
	foundPaths := existingPaths(paths)
	if len(foundPaths) != 0 {
		result, err := loader.All(foundPaths)
		if err != nil {
			return err
		}
		for name, module := range result.ParsedModules() {
			modules[name] = module
		}
		return nil
	}

	for filename, input := range embedded {
		module, err := ast.ParseModule(filename, input)
		if err != nil {
			return err
		}
		modules[filename] = module
	}
	return nil
}

func prepareBundledQuery(regoPackage string) (*rego.PreparedEvalQuery, error) {
	compiler, err := getBundledCompiler()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pq, err := rego.New(
		rego.Compiler(compiler),
		rego.Query(fmt.Sprintf("data.%s", regoPackage)),
		jsonFmtFunc(),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &pq, nil
}

func bundledCompilerCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	caps.Builtins = append(caps.Builtins, &ast.Builtin{
		Name: "jsonformat",
		Decl: types.NewFunction(types.Args(&types.Object{}), types.S),
	})
	return caps
}
