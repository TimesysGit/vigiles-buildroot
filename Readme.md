![Timesys Vigiles](https://www.timesys.com/wp-content/uploads/vigiles-cve-monitoring.png "Timesys Vigiles")


Timesys Vigiles For Buildroot
=============================

This is a collection of tools for image manifest generation used for security monitoring and notification as part of the **[Timesys Vigiles](https://www.timesys.com/security/vigiles/)** product offering.


What is Vigiles?
================

Vigiles is a vulnerability management tool that provides build-time CVE Analysis of Buildroot target images. It does this by collecting metadata about packages to be installed and uploading it to be compared against the Timesys CVE database.A high-level overview of the detected vulnerabilities is returned and a full detailed analysis can be viewed online.


Register (free) and download the API key to access the full feature set based on Vigiles Basic, Plus or Prime:
https://linuxlink.timesys.com/docs/wiki/engineering/LinuxLink_Key_File


Using Vigiles CVE Check
=======================

To generate a vulnerability report follow the below steps: 


1. Clone vigiles-buildroot repository at the same level as Buildroot directory.

	```sh
	git clone https://github.com/TimesysGit/vigiles-buildroot
	```

2. Download your LinuxLink Key File here and store it at the (recommended) path.

	```sh
	mkdir $HOME/timesys
	cp $HOME/Downloads/linuxlink_key $HOME/timesys/linuxlink_key
	```

	> Note: If the key is stored elsewhere, the location can be specified via the Buildroot configuration interface.
	>
	> See below for instructions.

3. Instruct Buildroot to include the Vigiles interface in its configuration.
	```sh
	make BR2_EXTERNAL=/path/to/vigiles-buildroot menuconfig
	```

	> Note: If you are already using an external Buildroot tree/interface, multiple paths can be concatenated, e.g.:

	>	```sh
 	>	make BR2_EXTERNAL=/path/to/other/external/buildroot/interface:/path/to/vigiles-buildroot menuconfig
	> ```

	> For more information on using external Buildroot interfaces, please see **[This Section of the Buildroot Documentation](https://buildroot.org/downloads/manual/manual.html#outside-br-custom)**

4. Execute Make with the Vigiles target
	```sh
	make vigiles-check
	```


5. View the Vigiles CVE (Text) Report Locally

	The CVE report will be located in the ```vigiles/``` subdirectory of your Buildroot build output, with a name based on the Target configuration; e.g.:
	```sh
	wc -l output/vigiles/buildroot-imx8mpico-report.txt
		3616 output/vigiles/buildroot-imx8mpico-report.txt
	```

6. View the Vigiles CVE Online Report

	The local CVE text report will contain a link to a comprehensive and graphical report; e.g.:
	```
	-- Vigiles CVE Report --
	        View detailed online report at:
	          https://linuxlink.timesys.com/cves/reports/< Unique Report Identifier>
	```

7. (Optional) Customize Your LinuxLink Vigiles Workspace

By default the manifest is uploaded to the "Private Workspace” product under your Vigiles account. To view other options and for more detailed information visit: https://github.com/TimesysGit/vigiles-buildroot

> Note: The manifest file that is generated for the report is also located in the ```vigiles/``` subdirectory
> of your build output; e.g.:
```sh
wc -l ts-output/vigiles/buildroot-imx8mpico-manifest.json 
	544 ts-output/vigiles/buildroot-imx8mpico-manifest.json
```

> This file may optionally be manually uploaded to Vigiles to generate a new CVE report.
> Click on Buildroot under “Upload manifest” on the Vigiles Dashboard page to do the same.

