
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
vigiles-opts	+= -e "$(vigiles-ecosystems)"
endif

ifeq ($(VIGILES_DOWNLOAD_SBOM),y)
vigiles-bin-path := $(call qstrip,$(BR2_EXTERNAL_VIGILES_CLI_BIN_PATH))
ifeq ($(strip $(vigiles-bin-path)),)
$(error Vigiles ERROR: Download SBOM is enabled, but the path to the vigiles CLI binary is not set. Please set it in menuconfig)
endif
vigiles-opts += --download-sbom
vigiles-opts += --vigiles-bin "$(vigiles-bin-path)"

ifeq ($(VIGILES_DOWNLOAD_SBOM_SPEC_CYCLONEDX),y)
vigiles-opts += --download-sbom-format "cyclonedx"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_SPEC_SPDX),y)
vigiles-opts += --download-sbom-format "spdx"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_SPEC_SPDX_LITE),y)
vigiles-opts += --download-sbom-format "spdx-lite"
endif

ifeq ($(VIGILES_DOWNLOAD_SBOM_FILE_JSON),y)
vigiles-opts += --download-sbom-file-type "json"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_FILE_XML),y)
vigiles-opts += --download-sbom-file-type "xml"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_FILE_YAML),y)
vigiles-opts += --download-sbom-file-type "yaml"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_FILE_TAG),y)
vigiles-opts += --download-sbom-file-type "tag"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_FILE_XLSX),y)
vigiles-opts += --download-sbom-file-type "xlsx"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_FILE_XLS),y)
vigiles-opts += --download-sbom-file-type "xls"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_FILE_RDFXML),y)
vigiles-opts += --download-sbom-file-type "rdfxml"
endif

ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_CDX_1_7),y)
vigiles-opts += --download-sbom-version "1.7"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_CDX_1_6),y)
vigiles-opts += --download-sbom-version "1.6"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_CDX_1_5),y)
vigiles-opts += --download-sbom-version "1.5"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_CDX_1_4),y)
vigiles-opts += --download-sbom-version "1.4"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_CDX_1_3),y)
vigiles-opts += --download-sbom-version "1.3"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_CDX_1_2),y)
vigiles-opts += --download-sbom-version "1.2"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_CDX_1_1),y)
vigiles-opts += --download-sbom-version "1.1"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_SPDX_2_3),y)
vigiles-opts += --download-sbom-version "2.3"
else ifeq ($(VIGILES_DOWNLOAD_SBOM_VERSION_SPDX_2_2),y)
vigiles-opts += --download-sbom-version "2.2"
endif
endif

# CycloneDX SBOMs cannot be upgraded or downgraded. If we generate CycloneDX
# 1.4 and also request a CycloneDX download, the requested download version
# must be 1.4.
ifeq ($(VIGILES_SBOM_FORMAT_CYCLONEDX_1.4),y)
ifeq ($(VIGILES_DOWNLOAD_SBOM_SPEC_CYCLONEDX),y)
ifneq ($(VIGILES_DOWNLOAD_SBOM_VERSION_CDX_1_4),y)
$(error Vigiles ERROR: For CycloneDX downloads, SBOM versions cannot be upgraded or downgraded when "CycloneDX 1.4 JSON" SBOM generation is selected. Please set the download SBOM version to 1.4 in menuconfig to download a CycloneDX SBOM in a different file type)
endif
endif
endif

ifneq ($(filter y,$(BR2_EXTERNAL_VIGILES) $(BR2_EXTERNAL_TIMESYS_VIGILES)),)
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

else 	#	ifeq ($(BR2_EXTERNAL_VIGILES),y)
vigiles-check vigiles-image:
	@$(call MESSAGE,"Vigiles Support is not Enabled.")

endif 	#	ifeq ($(BR2_EXTERNAL_VIGILES),y)

ifeq ($(BR2_EXTERNAL_TIMESYS_VIGILES),y)
$(info Vigiles WARNING: BR2_EXTERNAL_TIMESYS_VIGILES will be deprecated soon. Please update your configurations to use `BR2_EXTERNAL_VIGILES`.)
endif
