
vigiles-script-name	:= vigiles-buildroot.py
vigiles-script-dir	:= $(BR2_EXTERNAL_vigiles_PATH)/scripts
vigiles-script 		:= $(vigiles-script-dir)/$(vigiles-script-name)


ifeq ($(VIGILES_ENABLE_KERNEL_CONFIG),y)
vigiles-kconfig 	:= $(BR2_EXTERNAL_VIGILES_KERNEL_CONFIG)
else
vigiles-kconfig 	:= none
endif

ifeq ($(VIGILES_ENABLE_UBOOT_CONFIG),y)
vigiles-uconfig 	:= $(BR2_EXTERNAL_VIGILES_UBOOT_CONFIG)
else
vigiles-uconfig 	:= none
endif


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

ifeq ($(VIGILES_DEBUG_OUTPUT),y)
vigiles-opts += -D
endif

ifneq ($(vigiles-kconfig),auto)
vigiles-opts += -k $(vigiles-kconfig)
endif

ifneq ($(vigiles-uconfig),auto)
vigiles-opts += -u $(vigiles-uconfig)
endif


# Manifest/Report Amendments
vigiles-addl-file	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_INCLUDE_CSV))
ifneq ($(vigiles-addl-file),)
vigiles-opts	+= -A $(vigiles-addl-file)
endif

vigiles-excld-file	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_EXCLUDE_CSV))
ifneq ($(vigiles-excld-file),)
vigiles-opts	+= -E $(vigiles-excld-file)
endif

vigiles-whtlst-file	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_WHITELIST_CSV))
ifneq ($(vigiles-whtlst-file),)
vigiles-opts	+= -W $(vigiles-whtlst-file)
endif


ifeq ($(VIGILES_ENABLE_EXPERT),y)
ifeq ($(VIGILES_METADATA_ONLY),y)
vigiles-opts	+= --metadata-only
endif 	# ($(VIGILES_METADATA_ONLY),Y)
ifeq ($(VIGILES_GENERATE_INTERMEDIATE_FILES),y)
vigiles-opts	+= --write-intermediate
endif 	# ($(VIGILES_GENERATE_INTERMEDIATE_FILES),Y)
endif 	# ($(VIGILES_ENABLE_EXPERT),y)


ifeq ($(BR2_EXTERNAL_TIMESYS_VIGILES),y)
vigiles-check: target-finalize
	@$(call MESSAGE,"Running Vigiles CVE Check")
	(	\
		$(vigiles-env)		\
		$(vigiles-script)	\
		$(vigiles-opts)		\
	)

vigiles-image: target-finalize
	@$(call MESSAGE,"Generating Vigiles CVE Manifest")
	(	\
		$(vigiles-env)		\
		$(vigiles-script)	\
		$(vigiles-opts)		\
		--metadata-only 	\
	)

else 	#	ifeq ($(BR2_EXTERNAL_TIMESYS_VIGILES),y)
vigiles-check vigiles-image:
	@$(call MESSAGE,"Vigiles Support is not Enabled.")

endif 	#	ifeq ($(BR2_EXTERNAL_TIMESYS_VIGILES),y)

