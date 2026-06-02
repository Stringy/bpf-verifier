FSTAR_DIR := fstar
CACHE_DIR := $(FSTAR_DIR)/.cache

# F* modules in dependency order
# Topological order derived from `open BPF.*` imports
FSTAR_MODULES := \
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

CHECKED_FILES := $(patsubst %,$(CACHE_DIR)/%.fst.checked,$(FSTAR_MODULES))

.PHONY: test check-fstar clean-cache clean

test: check-fstar
	cargo test

check-fstar: $(CHECKED_FILES)

# Each checked file depends on its source and all earlier checked files.
# We use an order-only prerequisite on the cache directory.
$(CACHE_DIR):
	mkdir -p $@

# Generate a rule for each module: the checked file depends on its .fst
# source and all checked files earlier in the dependency chain.
prev :=
define MODULE_RULE
$(CACHE_DIR)/$(1).fst.checked: $(FSTAR_DIR)/$(1).fst $(prev) | $(CACHE_DIR)
	fstar.exe --include $(FSTAR_DIR) --cache_checked_modules --cache_dir $(CACHE_DIR) $$<
prev += $(CACHE_DIR)/$(1).fst.checked
endef

$(foreach mod,$(FSTAR_MODULES),$(eval $(call MODULE_RULE,$(mod))))

clean-cache:
	rm -rf $(CACHE_DIR)

clean: clean-cache
	cargo clean
