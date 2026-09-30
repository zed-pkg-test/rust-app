pub type ModuleKind {
  Lambda
  Http
  Rpc
  Actor
  Worker
}

pub opaque type Module(context, input, output) {
  Module(
    kind: ModuleKind,
    name: String,
    handle: fn(context, input) -> Result(output, String),
  )
}

pub fn module(
  kind: ModuleKind,
  name: String,
  handle: fn(context, input) -> Result(output, String),
) -> Module(context, input, output) {
  Module(kind: kind, name: name, handle: handle)
}

pub fn invoke(
  module_export: Module(context, input, output),
  context: context,
  input: input,
) -> Result(output, String) {
  let Module(_, _, handle) = module_export
  handle(context, input)
}
