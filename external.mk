
vigiles-script-name	:= vigiles-buildroot.py

ifneq ($(BR2_EXTERNAL_vigiles_PATH),)
vigiles-script-dir	:= $(BR2_EXTERNAL_vigiles_PATH)/scripts
else
vigiles-script-dir	:= $(BR2_EXTERNAL)/scripts
endif

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



vigiles-opts = -b $(BUILD_DIR)

vigiles-key-file	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_KEY_FILE))
ifneq ($(vigiles-key-file),)
vigiles-opts	+= -K $(vigiles-key-file)
endif

ifeq ($(VIGILES_ENABLE_DASHBOARD_CONFIG),y)
vigiles-dashboard	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_DASHBOARD_CONFIG))
ifneq ($(vigiles-dashboard),)
vigiles-opts	+= -C $(vigiles-dashboard)
endif
endif

ifneq ($(CANONICAL_CURDIR),)
vigiles-opts += -B $(CANONICAL_CURDIR)
else
vigiles-opts += -B $(CURDIR)
endif

ifneq ($(CANONICAL_O),)
vigiles-opts += -o $(CANONICAL_O)
else
vigiles-opts += -o $(O)
endif


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
vigiles-manifest-name 		:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_MANIFEST_NAME))
ifneq ($(vigiles-manifest-name),)
vigiles-opts		+= -N "$(vigiles-manifest-name)"
endif

vigiles-subfolder-name 		:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_SUBFOLDER_NAME))
ifneq ($(vigiles-subfolder-name),)
vigiles-opts		+= -F "$(vigiles-subfolder-name)"
endif

vigiles-addl-file	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_INCLUDE_CSV))
ifneq ($(vigiles-addl-file),)
vigiles-opts	+= -A "$(vigiles-addl-file)"
endif

vigiles-excld-file	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_EXCLUDE_CSV))
ifneq ($(vigiles-excld-file),)
vigiles-opts	+= -E "$(vigiles-excld-file)"
endif

vigiles-whtlst-file	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_WHITELIST_CSV))
ifneq ($(vigiles-whtlst-file),)
vigiles-opts	+= -W "$(vigiles-whtlst-file)"
endif

ifeq ($(BR2_EXTERNAL_VIGILES_UPLOAD_ONLY),y)
vigiles-opts	+= -U
endif


ifeq ($(VIGILES_ENABLE_EXPERT),y)
ifeq ($(VIGILES_GENERATE_INTERMEDIATE_FILES),y)
vigiles-opts	+= --write-intermediate
endif 	# ($(VIGILES_GENERATE_INTERMEDIATE_FILES),Y)
endif 	# ($(VIGILES_ENABLE_EXPERT),y)

ifeq ($(VIGILES_INCLUDE_VIRTUAL_PACKAGES),y)
vigiles-opts    += -v
endif

ifeq ($(VIGILES_GENERATE_SBOM_ONLY),y)
vigiles-opts    += -M
endif

vigiles-output	:= $(call qstrip,$(BR2_EXTERNAL_VIGILES_OUTPUT))
ifneq ($(vigiles-output),)
vigiles-opts	+= -O "$(vigiles-output)"
endif

ifeq ($(VIGILES_SBOM_FORMAT_VIGILES),y)
vigiles-opts    += -f "vigiles"
else ifeq ($(VIGILES_SBOM_FORMAT_CYCLONEDX_1.4),y)
vigiles-opts    += -f "cyclonedx_1.4"
endif

ifeq ($(VIGILES_NOTIFICATION_SUBSCRIBE),y)
    ifeq ($(VIGILES_NOTIFICATION_SUBSCRIBE_NONE),y)
        vigiles-opts    += -s "none"
    else ifeq ($(VIGILES_NOTIFICATION_SUBSCRIBE_DAILY),y)
        vigiles-opts    += -s "daily"
    else ifeq ($(VIGILES_NOTIFICATION_SUBSCRIBE_WEEKLY),y)
        vigiles-opts    += -s "weekly"
    else ifeq ($(VIGILES_NOTIFICATION_SUBSCRIBE_MONTHLY),y)
        vigiles-opts    += -s "monthly"
    endif
endif

ifeq ($(VIGILES_REQUIRE_ALL_CONFIGS),y)
vigiles-opts    += -c
endif

ifeq ($(VIGILES_REQUIRE_ALL_HASHFILES),y)
vigiles-opts    += -i
endif

vigiles-ecosystems	:= $(call qstrip,$(VIGILES_ECOSYSTEMS))
ifneq ($(vigiles-ecosystems),)
vigiles-opts	+= -e $(vigiles-ecosystems)
endif

ifeq ($(BR2_EXTERNAL_TIMESYS_VIGILES),y)
vigiles-check: target-finalize
	@$(call MESSAGE,"Running Vigiles CVE Check")
	(	\
		$(vigiles-script)	\
		$(vigiles-opts)		\
	)

vigiles-image: target-finalize
	@$(call MESSAGE,"Generating Vigiles CVE Manifest")
	(	\
		$(vigiles-script)	\
		$(vigiles-opts)		\
		--metadata-only 	\
	)

else 	#	ifeq ($(BR2_EXTERNAL_TIMESYS_VIGILES),y)
vigiles-check vigiles-image:
	@$(call MESSAGE,"Vigiles Support is not Enabled.")

endif 	#	ifeq ($(BR2_EXTERNAL_TIMESYS_VIGILES),y)

