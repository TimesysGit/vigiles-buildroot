
vigiles-script-name	:= vigiles-buildroot.py
vigiles-script-dir	:= $(BR2_EXTERNAL_vigiles_PATH)/scripts
vigiles-script 		:= $(vigiles-script-dir)/$(vigiles-script-name)


vigiles-kconfig 	:= $(BR2_EXTERNAL_VIGILES_KERNEL_CONFIG)
vigiles-kconfig 	?= none
vigiles-uconfig 	:= $(BR2_EXTERNAL_VIGILES_UBOOT_CONFIG)
vigiles-uconfig 	?= none

vigiles-key	:= $(BR2_EXTERNAL_VIGILES_KEY_FILE)

ifeq ($(VIGILES_ENABLE_DASHBOARD_CONFIG),y)
vigiles-dashboard	:= $(BR2_EXTERNAL_VIGILES_DASHBOARD_CONFIG)
else
vigiles-dashboard	:=
endif

vigiles-env = \
	VIGILES_KEY_FILE="$(vigiles-key)" \
	VIGILES_DASHBOARD_CONFIG="$(vigiles-dashboard)"

vigiles-opts = -B $(CANONICAL_CURDIR) -b $(BUILD_DIR) -o $(CANONICAL_O)

ifneq ($(vigiles-kconfig),auto)
vigiles-opts += "-k $(vigiles-kconfig)"
endif

ifneq ($(vigiles-uconfig),auto)
vigiles-opts += "-u $(vigiles-uconfig)"
endif


ifeq ($(VIGILES_ENABLE_EXPERT),y)
ifeq ($(VIGILES_METADATA_ONLY),y)
vigiles-opts	+= --metadata-only
endif 	# ($(VIGILES_METADATA_ONLY),Y)
ifeq ($(VIGILES_GENERATE_INTERMEDIATE_FILES),y)
vigiles-opts	+= --write-intermediate
endif 	# ($(VIGILES_GENERATE_INTERMEDIATE_FILES),Y)
endif 	# ($(VIGILES_ENABLE_EXPERT),y)

vigiles-check:
	@$(call MESSAGE,"Running Vigiles CVE Check")
	(	\
		$(vigiles-env)		\
		$(vigiles-script)	\
		$(vigiles-opts)		\
	)

vigiles-check: target-finalize
