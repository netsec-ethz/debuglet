// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 ETH Zurich

package workflow

func byteCatalog() []Block {
	return []Block{
		{"byte_payload", "Byte payload", "Data", "Decode text (UTF-8), hexadecimal byte pairs, or padded base64. size_bytes=-1 preserves all decoded bytes; 0 produces empty bytes; a positive size repeats and trims the decoded pattern to exactly that many bytes (up to 8192). Counts bytes, not characters. Connect base64 to a network payload/body and set its encoding to base64. Concatenate hex outputs to assemble binary fields.", true,
			[]Port{optional("value", "string", ""), optional("encoding", "string", "text"), optional("size_bytes", "number", float64(-1))},
			[]Port{output("base64", "string"), output("hex", "string"), output("bytes", "number")}, []string{}},
	}
}
