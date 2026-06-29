# === Object-level verification F* ===
OBJ_FSTAR_DIR := fstar/obj

OBJ_FSTAR_MODULES := \
	BPF.State \
	BPF.Helpers \
	BPF.Semantics \
	BPF.Spec \
	BPF.Verify \
	BPF.DefaultSpec \
	BPF.Check.StackBounds \
	BPF.Check.TypeSafety \
	BPF.Check.NullSafety \
	BPF.Witness \
	BPF.Exec.Safe \
	BPF.Exec.Path \
	BPF.Tactic \
	BPF.Tactic.Layered

# Checked files go next to the .fst files so F* finds them via --include
OBJ_CHECKED := $(patsubst %,$(OBJ_FSTAR_DIR)/%.fst.checked,$(OBJ_FSTAR_MODULES))

# === AST-level verification F* ===
AST_FSTAR_DIR := fstar/ast

AST_FSTAR_MODULES := \
	BPF.Integers \
	BPF.Tnum \
	BPF.Range \
	BPF.ValClass \
	BPF.VarCtx \
	BPF.AST.Types \
	BPF.AST.Expr \
	BPF.Helpers \
	BPF.AST.Stmt \
	BPF.AST.Decl

AST_TESTS := \
	tests/BPF.Test.SmokeTest \
	tests/BPF.Test.Negative

AST_CHECKED := $(patsubst %,$(AST_FSTAR_DIR)/%.fst.checked,$(AST_FSTAR_MODULES))
AST_TEST_CHECKED := $(patsubst %,$(AST_FSTAR_DIR)/%.fst.checked,$(AST_TESTS))

# === Targets ===
.PHONY: all test check-obj check-ast test-ast clean-cache clean image

all: check-obj check-ast test-ast

test: all
	cargo test

# --- Object-level F* ---
# Checked files are written next to .fst files via --cache_checked_modules.
# F* finds them there automatically on subsequent runs.
check-obj: $(OBJ_CHECKED)

prev :=
define OBJ_MODULE_RULE
$(OBJ_FSTAR_DIR)/$(1).fst.checked: $(OBJ_FSTAR_DIR)/$(1).fst $(prev)
	fstar.exe --include $(OBJ_FSTAR_DIR) --cache_checked_modules $$<
prev += $(OBJ_FSTAR_DIR)/$(1).fst.checked
endef

$(foreach mod,$(OBJ_FSTAR_MODULES),$(eval $(call OBJ_MODULE_RULE,$(mod))))

# --- AST-level F* ---
check-ast: $(AST_CHECKED)

ast_prev :=
define AST_MODULE_RULE
$(AST_FSTAR_DIR)/$(1).fst.checked: $(AST_FSTAR_DIR)/$(1).fst $(ast_prev)
	fstar.exe --include $(AST_FSTAR_DIR) --cache_checked_modules $$<
ast_prev += $(AST_FSTAR_DIR)/$(1).fst.checked
endef

$(foreach mod,$(AST_FSTAR_MODULES),$(eval $(call AST_MODULE_RULE,$(mod))))

test-ast: check-ast $(AST_TEST_CHECKED)

define AST_TEST_RULE
$(AST_FSTAR_DIR)/$(1).fst.checked: $(AST_FSTAR_DIR)/$(1).fst $(AST_CHECKED)
	fstar.exe --include $(AST_FSTAR_DIR) --include $(AST_FSTAR_DIR)/tests --cache_checked_modules $$<
endef

$(foreach mod,$(AST_TESTS),$(eval $(call AST_TEST_RULE,$(mod))))

# --- Cleanup ---
clean-cache:
	rm -f $(OBJ_FSTAR_DIR)/*.checked $(AST_FSTAR_DIR)/*.checked $(AST_FSTAR_DIR)/tests/*.checked

clean: clean-cache
	cargo clean

image:
	podman build -f Containerfile -t bpf-verifier .
