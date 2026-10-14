# Synthetic model and package metadata

These inert fixtures contain no executable payloads or real tensor weights.
`header-only.gguf`: GGUF v3 header, zero tensors/metadata; not a usable model.
`one.safetensors`: one F32 zero, bounded JSON shape/offset descriptor.
`minimal.onnx`: ModelProto ir_version=9, graph name=x, opset version=18;
only the protobuf envelope is inspected, not semantic ONNX validity.
`empty-archive.bin`: modern PyInstaller cookie with an empty archive/TOC.
All fixtures are inventory examples, not evidence of an agent or execution.
