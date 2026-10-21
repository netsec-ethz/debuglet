// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"net"
	"net/url"
	"slices"
	"strconv"
)

// Generate produces ordinary Go source for one WASI guest. Destination metadata
// contains static hints only; the normal submission policy remains authoritative.
func Generate(w Workflow) (Program, error) {
	if w.Experiment != nil {
		return Program{}, fmt.Errorf("build experiment context through the whole experiment")
	}
	return generate(w, "")
}

func generate(w Workflow, experimentConfig string) (Program, error) {
	encoded, err := json.Marshal(w)
	if err != nil {
		return Program{}, err
	}
	if len(encoded) > 1024*1024 {
		return Program{}, fmt.Errorf("workflow exceeds 1 MiB")
	}
	hash := sha256.Sum256(encoded)
	digest := hex.EncodeToString(hash[:])
	// JSON is also the boundary for callers constructing Workflow directly in Go.
	if err = json.Unmarshal(encoded, &w); err != nil {
		return Program{}, err
	}
	if ds := Validate(w); len(ds) > 0 {
		return Program{}, fmt.Errorf("invalid workflow: %s", ds[0].Message)
	}
	if experimentConfig == "" {
		for _, n := range w.Nodes {
			if n.Block == "send_message" || n.Block == "await_message" || n.Block == "phase_barrier" {
				return Program{}, fmt.Errorf("%s requires building the whole experiment", n.Block)
			}
		}
	}
	catalog := catalogFor(w)
	indexes := map[string]int{}
	nodes := map[string]Node{}
	for i, n := range w.Nodes {
		indexes[n.ID] = i
		nodes[n.ID] = n
	}
	data := map[Endpoint]Endpoint{}
	control := map[Endpoint]string{}
	adj := map[string][]string{}
	for _, e := range w.Edges {
		if e.Kind == "data" {
			data[e.To] = e.From
		} else {
			control[e.From] = e.To.Node
			adj[e.From.Node] = append(adj[e.From.Node], e.To.Node)
		}
	}
	custom := map[string]int{}
	for i, c := range w.CustomBlocks {
		custom[c.ID] = i
	}
	var out bytes.Buffer
	out.WriteString("// Generated measurement program. Edit its workflow source to regenerate.\npackage main\nimport(\"encoding/json\";\"fmt\";\"os\";\"github.com/netsec-ethz/debuglet/pkg/workflow/guest\";")
	for _, path := range customImports(w) {
		fmt.Fprintf(&out, "%q;", path)
	}
	fmt.Fprintf(&out, ")\nvar runtime=guest.New(%q)\n", digest)
	out.WriteString("func literal(s string)any{var v any;if err:=json.Unmarshal([]byte(s),&v);err!=nil{panic(err)};return v}\n")
	if experimentConfig == "" {
		fmt.Fprintf(&out, "func main(){if err:=run%d();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}\n", indexes[w.Entry])
	} else {
		manifest, err := json.Marshal(struct {
			Schema           string    `json:"schema"`
			WorkflowSHA256   string    `json:"workflow_sha256"`
			ExperimentSHA256 string    `json:"experiment_sha256"`
			Participant      string    `json:"participant"`
			Participants     []string  `json:"participants"`
			Channels         []Channel `json:"channels"`
		}{"debuglet.experiment.v1", digest, w.Experiment.Fingerprint, w.Experiment.Participant, w.Experiment.Participants, w.Experiment.Channels})
		if err != nil {
			return Program{}, err
		}
		if len(manifest) > 65536 {
			return Program{}, fmt.Errorf("experiment manifest exceeds 64 KiB")
		}
		out.WriteString("var experiment *guest.Experiment\n")
		// Retain the declared graph even if readiness fails before the first block.
		fmt.Fprintf(&out, "func main(){if _,err:=fmt.Fprintln(os.Stdout,%q);err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)};var err error;experiment,err=guest.JoinExperiment(%q);if err==nil{err=run%d()};if err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}\n", string(manifest), experimentConfig, indexes[w.Entry])
	}
	for i, c := range w.CustomBlocks {
		fmt.Fprintf(&out, "// Custom block %s\nfunc custom%d(inputs map[string]any)(map[string]any,error){\n%s\n}\n", c.ID, i, c.Code)
	}
	for i, n := range w.Nodes {
		b := catalog[n.Block]
		fmt.Fprintf(&out, "// Inputs for node %s (%s).\nfunc inputs%d()(map[string]any,error){\nin:=map[string]any{}\n", n.ID, n.Block, i)
		assigned := []Port{}
		for _, p := range b.Inputs {
			if from, ok := data[Endpoint{n.ID, p.Name}]; ok {
				fmt.Fprintf(&out, "{value,err:=value%d(%q);if err!=nil{return nil,fmt.Errorf(%q,err)};in[%q]=value}\n", indexes[from.Node], from.Port, "input "+p.Name+": %w", p.Name)
				assigned = append(assigned, p)
				continue
			}
			value, ok := n.Inputs[p.Name]
			if !ok {
				value = p.Default
				if value == nil {
					continue
				}
			}
			v, _ := json.Marshal(value)
			fmt.Fprintf(&out, "in[%q]=literal(%q)\n", p.Name, string(v))
			assigned = append(assigned, p)
		}
		fmt.Fprintf(&out, "if err:=guest.Check(in,%s);err!=nil{return nil,err};return in,nil}\n", typeMap(assigned))
		fmt.Fprintf(&out, "func value%d(port string)(any,error){\n", i)
		if b.Pure {
			fmt.Fprintf(&out, "in,err:=inputs%d();if err!=nil{return nil,runtime.Fail(%q,%q,err)}\nvalues,err:=guest.Pure(%q,in);if err!=nil{return nil,runtime.Fail(%q,%q,err)}\nif err=guest.Check(values,%s);err!=nil{return nil,runtime.Fail(%q,%q,err)}\nif err=runtime.Record(%q,%q,values);err!=nil{return nil,err}\n", i, n.ID, n.Block, n.Block, n.ID, n.Block, typeMap(b.Outputs), n.ID, n.Block, n.ID, n.Block)
		}
		fmt.Fprintf(&out, "return runtime.Output(%q,port)}\n", n.ID)
		if b.Pure {
			continue
		}
		fmt.Fprintf(&out, "// Execute node %s (%s).\nfunc run%d()error{\nif err:=runtime.Step();err!=nil{return runtime.Fail(%q,%q,err)}\nin,err:=inputs%d();if err!=nil{return runtime.Fail(%q,%q,err)}\n", n.ID, n.Block, i, n.ID, n.Block, i, n.ID, n.Block)
		callNext := func(port string) {
			if next, ok := control[Endpoint{n.ID, port}]; ok {
				fmt.Fprintf(&out, "return run%d()\n", indexes[next])
			} else {
				out.WriteString("return nil\n")
			}
		}
		switch n.Block {
		case "if":
			fmt.Fprintf(&out, "if err=runtime.Record(%q,%q,map[string]any{});err!=nil{return err}\nif in[\"condition\"].(bool){\n", n.ID, n.Block)
			callNext("true")
			out.WriteString("}\n")
			callNext("false")
		case "repeat":
			fmt.Fprintf(&out, "count,err:=guest.RepeatCount(in[\"count\"]);if err!=nil{return runtime.Fail(%q,%q,err)}\nfor iteration:=1;iteration<=count;iteration++{\n", n.ID, n.Block)
			body := control[Endpoint{n.ID, "body"}]
			bodyNodes := reachable(body, adj)
			ids := make([]string, 0, len(bodyNodes))
			for id := range bodyNodes {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			out.WriteString("runtime.Forget(")
			for _, id := range ids {
				fmt.Fprintf(&out, "%q,", id)
			}
			out.WriteString(")\n")
			fmt.Fprintf(&out, "if err=runtime.Record(%q,%q,map[string]any{\"iteration\":float64(iteration)});err!=nil{return err}\nif err=run%d();err!=nil{return err}\n}\n", n.ID, n.Block, indexes[body])
			callNext("done")
		case "wait":
			fmt.Fprintf(&out, "if err=guest.Wait(in[\"duration_ms\"]);err!=nil{return runtime.Fail(%q,%q,err)}\nif err=runtime.Record(%q,%q,map[string]any{});err!=nil{return err}\n", n.ID, n.Block, n.ID, n.Block)
			callNext("next")
		default:
			switch n.Block {
			case "send_message":
				out.WriteString("values,err:=experiment.Send(in)\n")
			case "await_message":
				out.WriteString("values,err:=experiment.Await(in)\n")
			case "phase_barrier":
				out.WriteString("values,err:=experiment.Barrier(in)\n")
			case "start_timer":
				out.WriteString("_ = in\nvalues,err:=runtime.StartTimer()\n")
			case "elapsed":
				out.WriteString("values,err:=runtime.Elapsed(in)\n")
			case "create_collection":
				out.WriteString("_ = in\nvalues,err:=runtime.CreateCollection()\n")
			case "collect":
				out.WriteString("values,err:=runtime.Collect(in)\n")
			case "read_collection":
				out.WriteString("values,err:=runtime.ReadCollection(in)\n")
			case "reset_collection":
				out.WriteString("values,err:=runtime.ResetCollection(in)\n")
			case "dns_query":
				out.WriteString("values,err:=guest.DNSQuery(in)\n")
			case "udp_exchange":
				out.WriteString("values,err:=guest.UDPExchange(in)\n")
			case "tcp_exchange":
				out.WriteString("values,err:=guest.TCPExchange(in)\n")
			case "tls_inspect":
				out.WriteString("values,err:=guest.TLSInspect(in)\n")
			case "hop_probe":
				out.WriteString("values,err:=guest.HopProbe(in)\n")
			case "udp_listener":
				out.WriteString("values,err:=guest.UDPListener(in)\n")
			case "udp_receive":
				out.WriteString("values,err:=guest.UDPReceive(in)\n")
			case "udp_reply":
				out.WriteString("values,err:=guest.UDPReply(in)\n")
			case "http":
				out.WriteString("values,err:=guest.HTTP(in)\n")
			case "tcp_connect":
				out.WriteString("values,err:=guest.TCPConnect(in)\n")
			case "ping":
				out.WriteString("values,err:=guest.Ping(in)\n")
			case "emit":
				out.WriteString("values:=in\n")
			case "report_metric", "report_table", "report_text":
				fmt.Fprintf(&out, "values,err:=guest.Report(%q,in)\n", n.Block)
			default:
				fmt.Fprintf(&out, "values,err:=guest.RunCustom(custom%d,in)\n", custom[n.Block])
			}
			fmt.Fprintf(&out, "if err!=nil{return runtime.Fail(%q,%q,err)}\nif err=guest.Check(values,%s);err!=nil{return runtime.Fail(%q,%q,err)}\nif err=runtime.Record(%q,%q,values);err!=nil{return runtime.Fail(%q,%q,err)}\n", n.ID, n.Block, typeMap(b.Outputs), n.ID, n.Block, n.ID, n.Block, n.ID, n.Block)
			callNext("next")
		}
		out.WriteString("}\n")
	}
	source, err := format.Source(out.Bytes())
	if err != nil {
		return Program{}, fmt.Errorf("format generated program: %w", err)
	}
	program := Program{Source: string(source), WorkflowSHA256: digest, Destinations: []string{}}
	for _, n := range w.Nodes {
		if n.Block == "ping" || n.Block == "hop_probe" {
			program.RequireICMP = true
		}
		if n.Block == "udp_listener" || n.Block == "udp_receive" || n.Block == "udp_reply" {
			program.RequireUDPListener = true
		}
		if function := map[string]string{"tls_inspect": "tls_inspect", "hop_probe": "hop_probe", "udp_receive": "receive_udp", "udp_reply": "reply_udp"}[n.Block]; function != "" {
			name := "debuglet_io_v1." + function
			if !slices.Contains(program.RequiredHostFunctions, name) {
				program.RequiredHostFunctions = append(program.RequiredHostFunctions, name)
			}
		}
		field := "target"
		if n.Block == "http" {
			field = "url"
		} else if n.Block == "dns_query" {
			field = "resolver"
		} else if n.Block == "udp_reply" {
			field = "destination"
		} else if !slices.Contains([]string{"ping", "tcp_connect", "udp_exchange", "tcp_exchange", "tls_inspect", "hop_probe"}, n.Block) {
			continue
		}
		value := n.Inputs[field]
		if from, ok := data[Endpoint{n.ID, field}]; ok {
			source := nodes[from.Node]
			if source.Block == "constant" {
				value = source.Inputs["value"]
			} else {
				continue
			}
		}
		target, ok := value.(string)
		if !ok {
			continue
		}
		if n.Block == "http" {
			u, e := url.Parse(target)
			if e != nil {
				continue
			}
			target = u.Hostname()
		} else if n.Block != "ping" && n.Block != "hop_probe" {
			host, _, e := net.SplitHostPort(target)
			if e != nil {
				continue
			}
			target = host
		}
		if target != "" && !slices.Contains(program.Destinations, target) {
			program.Destinations = append(program.Destinations, target)
		}
	}
	slices.Sort(program.Destinations)
	slices.Sort(program.RequiredHostFunctions)
	return program, nil
}
func typeMap(ports []Port) string {
	var out bytes.Buffer
	out.WriteString("map[string]string{")
	for _, p := range ports {
		fmt.Fprintf(&out, "%s:%s,", strconv.Quote(p.Name), strconv.Quote(p.Type))
	}
	out.WriteString("}")
	return out.String()
}

// Custom blocks can refer to a fixed set of available packages. Their bodies
// cannot add project files, compiler directives or arbitrary imports.
func customImports(w Workflow) []string {
	allowed := map[string]string{"debuglet": "github.com/netsec-ethz/debuglet/pkg/debuglet", "time": "time", "strings": "strings", "math": "math"}
	used := map[string]bool{}
	for _, block := range w.CustomBlocks {
		file, err := parser.ParseFile(token.NewFileSet(), "custom.go", "package main\nfunc custom(inputs map[string]any)(map[string]any,error){\n"+block.Code+"\n}", 0)
		if err != nil {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name, ok := selector.X.(*ast.Ident)
			if ok && name.Obj == nil {
				if path, found := allowed[name.Name]; found {
					used[path] = true
				}
			}
			return true
		})
	}
	paths := make([]string, 0, len(used))
	for path := range used {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}
