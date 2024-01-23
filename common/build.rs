use protobuf_codegen::Codegen;

fn main() {
    Codegen::new()
        .pure()
        .cargo_out_dir("common")
        .input("src/proto/env.proto")
        .include("src/proto")
        .run_from_script();
}
