# gmutils/Makefile — Build & package genmeta for deb + homebrew + scoop
#
# Usage:
#   make deb              Build all deb architectures
#   make homebrew          Build homebrew formula (macOS only)
#   make scoop             Build scoop manifest (Linux, cross-compile to Windows)
#   make -n deb            Dry run
#   make -j4 deb           Parallel build

BUILDX_DIR := $(or $(BUILDX_DIR),$(HOME)/code/reimu/genmeta-buildx)
include $(BUILDX_DIR)/archs.mk

# --- Project metadata (from Cargo.toml) ---
CARGO_NAME := genmeta
VERSION  := $(shell cargo metadata --no-deps --format-version=1 \
              | python3 -c "import sys,json; pkgs=json.loads(sys.stdin.read())['packages']; print(next(p['version'] for p in pkgs if p['name']=='$(CARGO_NAME)'))")
DESCRIPTION := $(shell cargo metadata --no-deps --format-version=1 \
              | python3 -c "import sys,json; pkgs=json.loads(sys.stdin.read())['packages']; print(next(p['description'] for p in pkgs if p['name']=='$(CARGO_NAME)'))")
HOMEPAGE := $(shell cargo metadata --no-deps --format-version=1 \
              | python3 -c "import sys,json; pkgs=json.loads(sys.stdin.read())['packages']; print(next(p['homepage'] or '' for p in pkgs if p['name']=='$(CARGO_NAME)'))")
LICENSE  := $(shell cargo metadata --no-deps --format-version=1 \
              | python3 -c "import sys,json; pkgs=json.loads(sys.stdin.read())['packages']; print(next(p['license'] or '' for p in pkgs if p['name']=='$(CARGO_NAME)'))")

# --- Deb configuration ---
DEB_ARCHS    := amd64 arm64 armhf
DEB_NAME     := gmutils
DEB_REMOTE   := ubuntu@download.genmeta.net:/data/wwwroot/ppa/deb/main
DOCKER_IMG   := $(DOCKER_IMG_UBUNTU20)
DEBS_DIR     := $(CURDIR)/debs/gmutils

# --- Homebrew configuration ---
BREW_ARCHS     := apple intel
BREW_REMOTE    := ubuntu@download.genmeta.net:/data/wwwroot/homebrew
BREW_DL_URL    := https://download.genmeta.net/homebrew
BREW_CONTENT   := genmeta/homebrew_content.rb
BREW_OUTPUT    := homebrew-genmeta/genmeta.rb

# --- Scoop configuration ---
SCOOP_ARCHS   := 64bit 32bit
SCOOP_REMOTE  := ubuntu@download.genmeta.net:/data/wwwroot/scoop
SCOOP_DL_URL  := https://download.genmeta.net/scoop
SCOOP_OUTPUT  := scoop-genmeta/genmeta.json

# --- Docker helpers ---
CARGO_MOUNTS = \
	-v $(CARGO_HOME_DIR)/config.toml:/cargo/config.toml \
	-v $(CARGO_HOME_DIR)/git:/cargo/git \
	-v $(CARGO_HOME_DIR)/registry:/cargo/registry

define docker_image_tag
$(DOCKER_IMG)-$(ARCH_$(1)_LLVM):$(DEB_NAME)
endef

define docker_ensure_image
	@mkdir -p base_images_cache
	@echo 'FROM $(DOCKER_IMG)' > base_images_cache/$(DEB_NAME)-$(1).dockerfile
	@echo 'RUN /cargo/bin/rustup target add $(ARCH_$(1)_LLVM)' >> base_images_cache/$(DEB_NAME)-$(1).dockerfile
	@echo 'RUN dpkg --add-architecture $(ARCH_$(1)_DEB) && apt-get update && apt-get install --assume-yes libc-dev:$(ARCH_$(1)_DEB)' >> base_images_cache/$(DEB_NAME)-$(1).dockerfile
	$(CONTAINER_ENGINE) buildx build \
		-t $(DOCKER_IMG) \
		-f $(BUILDX_DIR)/base_images/$(DOCKER_IMG).dockerfile \
		$(BUILDX_DIR)/base_images
	$(CONTAINER_ENGINE) buildx build \
		-t $(call docker_image_tag,$(1)) \
		-f base_images_cache/$(DEB_NAME)-$(1).dockerfile \
		$(BUILDX_DIR)/base_images
endef

# ============================================================
# Deb targets
# ============================================================

define deb_target
.PHONY: deb-$(1)
deb-$(1): | $(DEBS_DIR)
	$(call docker_ensure_image,$(1))
	$(CONTAINER_ENGINE) run --rm \
		$(CARGO_MOUNTS) \
		-v $(CURDIR):/app \
		-v $(DEBS_DIR):/debs \
		$(call docker_image_tag,$(1)) \
		bash -c "\
			source /cargo/env; \
			export RUSTFLAGS=\"$$$${RUSTFLAGS:-} -L /usr/lib/$(ARCH_$(1)_GNU)\"; \
			cargo zigbuild --release --target $(ARCH_$(1)_LLVM) --bin $(CARGO_NAME); \
			cargo deb -p $(CARGO_NAME) --target $(ARCH_$(1)_LLVM) --no-build --no-strip; \
			cp target/$(ARCH_$(1)_LLVM)/debian/*.deb /debs/"
endef

$(foreach arch,$(DEB_ARCHS),$(eval $(call deb_target,$(arch))))

.PHONY: deb
deb: $(addprefix deb-,$(DEB_ARCHS)) ## Build all deb packages

$(DEBS_DIR):
	mkdir -p $@

# ============================================================
# Homebrew targets (macOS native build)
# ============================================================

define brew_build_target
.PHONY: brew-build-$(1)
brew-build-$(1):
	cargo build --release --target $(ARCH_$(1)_LLVM) --bin $(CARGO_NAME)
	@mkdir -p target/$(ARCH_$(1)_LLVM)/homebrew/$(CARGO_NAME)/formula
	cp target/$(ARCH_$(1)_LLVM)/release/$(CARGO_NAME) target/$(ARCH_$(1)_LLVM)/homebrew/$(CARGO_NAME)/formula/
	cp genmeta-ssh.sh target/$(ARCH_$(1)_LLVM)/homebrew/$(CARGO_NAME)/formula/
	tar czf target/$(ARCH_$(1)_LLVM)/homebrew/$(CARGO_NAME)/$(CARGO_NAME)_$(VERSION)_$(1).tar.gz \
		-C target/$(ARCH_$(1)_LLVM)/homebrew/$(CARGO_NAME)/formula .
endef

$(foreach arch,$(BREW_ARCHS),$(eval $(call brew_build_target,$(arch))))

.PHONY: homebrew
homebrew: $(addprefix brew-build-,$(BREW_ARCHS)) ## Build all archs + generate formula
	@mkdir -p homebrew-genmeta
	python3 $(BUILDX_DIR)/gen_formula.py \
		--name "$(CARGO_NAME)" --version "$(VERSION)" \
		--description "$(DESCRIPTION)" \
		--homepage "$(HOMEPAGE)" \
		--content-file "$(BREW_CONTENT)" \
		--download-url "$(BREW_DL_URL)" \
		$(foreach arch,$(BREW_ARCHS),--arch $(arch):target/$(ARCH_$(arch)_LLVM)/homebrew/$(CARGO_NAME)/$(CARGO_NAME)_$(VERSION)_$(arch).tar.gz) \
		--output "$(BREW_OUTPUT)"

# ============================================================
# Scoop targets (Linux cross-compile to Windows via cargo-xwin)
# ============================================================

define scoop_build_target
.PHONY: scoop-build-$(1)
scoop-build-$(1):
	cargo xwin build --release --target $(ARCH_$(1)_LLVM) --bin $(CARGO_NAME)
	@mkdir -p target/$(ARCH_$(1)_LLVM)/scoop/$(CARGO_NAME)/package
	cp target/$(ARCH_$(1)_LLVM)/release/$(CARGO_NAME).exe target/$(ARCH_$(1)_LLVM)/scoop/$(CARGO_NAME)/package/
	cp genmeta-ssh.bat target/$(ARCH_$(1)_LLVM)/scoop/$(CARGO_NAME)/package/
	tar czf target/$(ARCH_$(1)_LLVM)/scoop/$(CARGO_NAME)/$(CARGO_NAME)_$(VERSION)_$(1).tar.gz \
		-C target/$(ARCH_$(1)_LLVM)/scoop/$(CARGO_NAME)/package .
endef

$(foreach arch,$(SCOOP_ARCHS),$(eval $(call scoop_build_target,$(arch))))

.PHONY: scoop
scoop: $(addprefix scoop-build-,$(SCOOP_ARCHS)) ## Build all archs + generate scoop manifest
	python3 $(BUILDX_DIR)/gen_scoop_manifest.py \
		--name "$(CARGO_NAME)" --version "$(VERSION)" \
		--description "$(DESCRIPTION)" \
		--license "$(LICENSE)" \
		--homepage "$(HOMEPAGE)" \
		--download-url "$(SCOOP_DL_URL)" \
		--bin genmeta.exe --bin genmeta-ssh.bat \
		$(foreach arch,$(SCOOP_ARCHS),--arch $(arch):target/$(ARCH_$(arch)_LLVM)/scoop/$(CARGO_NAME)/$(CARGO_NAME)_$(VERSION)_$(arch).tar.gz) \
		--output "$(SCOOP_OUTPUT)"

# ============================================================
# Upload targets
# ============================================================

.PHONY: upload-deb
upload-deb: ## Upload deb packages
	$(RSYNC) $(DEBS_DIR)/*.deb $(DEB_REMOTE)

.PHONY: upload-homebrew
upload-homebrew: ## Upload homebrew formula + archives
	$(RSYNC) $(BREW_OUTPUT) \
		$(foreach arch,$(BREW_ARCHS),target/$(ARCH_$(arch)_LLVM)/homebrew/$(CARGO_NAME)/$(CARGO_NAME)_$(VERSION)_$(arch).tar.gz) \
		$(BREW_REMOTE)

.PHONY: upload-scoop
upload-scoop: ## Upload scoop manifest + archives
	$(RSYNC) $(SCOOP_OUTPUT) \
		$(foreach arch,$(SCOOP_ARCHS),target/$(ARCH_$(arch)_LLVM)/scoop/$(CARGO_NAME)/$(CARGO_NAME)_$(VERSION)_$(arch).tar.gz) \
		$(SCOOP_REMOTE)

# ============================================================
# Convenience
# ============================================================

.PHONY: all
all: deb homebrew scoop ## Build everything

.PHONY: upload
upload: upload-deb upload-homebrew upload-scoop ## Upload everything

.PHONY: clean
clean:
	rm -rf $(DEBS_DIR) base_images_cache homebrew-genmeta
	rm -rf target/*/homebrew target/*/scoop

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
