# === Object-level verification F* ===
OBJ_FSTAR_DIR := fstar/obj
OBJ_CACHE_DIR := $(OBJ_FSTAR_DIR)/.cache

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

OBJ_CHECKED := $(patsubst %,$(OBJ_CACHE_DIR)/%.fst.checked,$(OBJ_FSTAR_MODULES))

# === AST-level verification F* ===
AST_FSTAR_DIR := fstar/ast
AST_CACHE_DIR := $(AST_FSTAR_DIR)/_cache

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

AST_CHECKED := $(patsubst %,$(AST_CACHE_DIR)/%.fst.checked,$(AST_FSTAR_MODULES))
AST_TEST_CHECKED := $(patsubst %,$(AST_CACHE_DIR)/%.fst.checked,$(AST_TESTS))

# === Targets ===
.PHONY: all test check-obj check-ast test-ast clean-cache clean image

all: check-obj check-ast test-ast

test: all
	cargo test

# --- Object-level F* ---
check-obj: $(OBJ_CHECKED)

$(OBJ_CACHE_DIR):
	mkdir -p $@

prev :=
define OBJ_MODULE_RULE
$(OBJ_CACHE_DIR)/$(1).fst.checked: $(OBJ_FSTAR_DIR)/$(1).fst $(prev) | $(OBJ_CACHE_DIR)
	fstar.exe --include $(OBJ_FSTAR_DIR) --cache_checked_modules --cache_dir $(OBJ_CACHE_DIR) $$<
prev += $(OBJ_CACHE_DIR)/$(1).fst.checked
endef

$(foreach mod,$(OBJ_FSTAR_MODULES),$(eval $(call OBJ_MODULE_RULE,$(mod))))

# --- AST-level F* ---
check-ast: $(AST_CHECKED)

$(AST_CACHE_DIR):
	mkdir -p $@

ast_prev :=
define AST_MODULE_RULE
$(AST_CACHE_DIR)/$(1).fst.checked: $(AST_FSTAR_DIR)/$(1).fst $(ast_prev) | $(AST_CACHE_DIR)
	fstar.exe --include $(AST_FSTAR_DIR) --cache_checked_modules --cache_dir $(AST_CACHE_DIR) $$<
ast_prev += $(AST_CACHE_DIR)/$(1).fst.checked
endef

$(foreach mod,$(AST_FSTAR_MODULES),$(eval $(call AST_MODULE_RULE,$(mod))))

test-ast: check-ast $(AST_TEST_CHECKED)

define AST_TEST_RULE
$(AST_CACHE_DIR)/$(1).fst.checked: $(AST_FSTAR_DIR)/$(1).fst $(AST_CHECKED) | $(AST_CACHE_DIR)
	fstar.exe --include $(AST_FSTAR_DIR) --include $(AST_FSTAR_DIR)/tests --cache_checked_modules --cache_dir $(AST_CACHE_DIR) $$<
endef

$(foreach mod,$(AST_TESTS),$(eval $(call AST_TEST_RULE,$(mod))))

# --- Cleanup ---
clean-cache:
	rm -rf $(OBJ_CACHE_DIR) $(AST_CACHE_DIR)

clean: clean-cache
	cargo clean

image:
	podman build -f Containerfile -t bpf-verifier .
