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

    >   ```sh
    >   make BR2_EXTERNAL=/path/to/other/external/buildroot/interface:/path/to/vigiles-buildroot menuconfig
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

    #### The CVE Manifest
    The Vigiles CVE Scanner creates a manifest that it sends to the LinuxLink
    Server describing your build configuration. This manifest is located in the
    ```vigiles/``` subdirectory of your Buildroot output (the same location as
    the text report it receives back).
    ```sh
    wc -l output/vigiles/buildroot-imx8mpico-manifest.json 
        557 output/vigiles/buildroot-imx8mpico-manifest.json
    ```
    In the event that something goes wrong, or if the results seem incorrect,
    this file may offer insight as to why. It's important to include this file
    with any support request.


Configuration
=============

If included, Timesys Vigiles will be enabled by default with the Kconfig option
**```BR2_EXTERNAL_TIMESYS_VIGILES```**. In addition, there are other configuration
options available to control the behavior of the subsystem.

> **Note About Pathnames**
>
> Pathnames that are specified follow the same semantics as throughout the
> Buildroot build system
> * Non-absolute paths are relative to the top of the Buildroot source.
>
> * Variables from both the shell and make environments are accessible using
> 'make' syntax; e.g. *```$(HOME)```, ```$(BUILD_DIR)```, ```$(TOPDIR)```*
>
> * Shell expansion is not available; i.e. *```~/```* will not reference
> a user's home directory. Use *```$(HOME)/```* instead.

### Base Configuration

Using ```make menuconfig```, the Vigiles configuration menu can be found under
**```External Options```**.

```
External options  ---> 
    *** Timesys Vigiles CVE Checker (in /home/mochel/projects/buildroot/vigiles) ***
    [*] Enable Timesys Vigiles CVE Check  --->
```

### Reporting and Filtering

Linux Kernel and U-Boot .config filtering can be enabled/disabled using the options
**```VIGILES_ENABLE_KERNEL_CONFIG```** and **```VIGILES_ENABLE_UBOOT_CONFIG```**.

If using a custom location for either the Kernel or U-Boot .config files, the
paths can be specified using **```BR2_EXTERNAL_VIGILES_KERNEL_CONFIG```** and
**```BR2_EXTERNAL_VIGILES_UBOOT_CONFIG```**.

The default for both paths is _```auto```_ which results in automatically using
the .config from the package's configured build directory. It is recommended
that this value is used unless it is absolutely necessary to specify an
alternative path.

```
              *** Vigiles Kernel CVE Reporting Options ***
        [*]   Enable Linux Kernel .config Filtering
        (auto)  Location of Linux Kernel .config file
        [*]   Enable U-Boot .config Filtering
        (auto)  Location of U-Boot .config file
```

> **Note:**
> 
> Linux Kernel .config filtering is only enabled if ```Kernel ---> [*] Linux Kernel ```
>  (**```BR2_LINUX_KERNEL```**) is enabled.
>
> U-Boot .config filtering is enabled only if ```Bootloaders  --->  [*] U-Boot ```
> (**```BR2_TARGET_UBOOT```**) is enabled.


### Customizing / Amending the Vigiles Report

In some cases, it's desirable to modify the CVE report that Vigiles generates.
vigiles-buildroot supports the ability to _Include Additional Packages_,
_Exclude Packages_ and _Whitelist Known CVEs_. In addition, the file names of
the locally-generated Manifest and CVE Report may be customized.

All of these options are supported by a ```Kconfig``` option where a user may
specify a CSV (comma-separated-value) file that describe the packages or CVEs.
Each is described below.


#### Manifest and Report Naming

By default, the file names of the Vigiles Manifest to be uploaded and the CVE
Report that is generated are given names based on the values of
```BR2_HOSTNAME``` and ```BR2_DEFCONFIG``` (or the target CPU), which will
produce files like this:

```sh
output/vigiles
├── buildroot-nitrogen6x-manifest.json
└── buildroot-nitrogen6x-report.txt
```


To use a custom name for the local Vigiles Manifest that is uploaded and the
CVE Report that is generated, the Kconfig option
```BR2_EXTERNAL_VIGILES_MANIFEST_NAME```
can be used. If set to '**Custom-Name**', the files produced will be:

```sh
output/vigiles
├── Custom-Name-manifest.json
└── Custom-Name-report.txt
```


#### Including Additional Packages

To include packages that are built outisde of the standard Buildroot process
(and therefore wouldn't be included in the Vigiles CVE Report), the Kconfig
option ```BR2_EXTERNAL_VIGILES_INCLUDE_CSV``` ("Additional Packages to Include
in Report") may be set to the path of a CSV file. 

>Example: ```$(HOME)/projects/buildroot/vigiles-additional-packages.csv```

The CSV file consists of an optional header and the following fields:

* Product - the CPE Name that packages use in CVEs
* (optional) Version - the version of the package used.
* (optional) License - the license of the package used

The following example shows the accepted syntax for expressing extra packages:

```sh
$ cat $HOME/projects/buildroot/vigiles-additional-packages.csv
product,version,license
avahi,0.6
bash,4.0
bash,4.1,GPL 3.0
busybox,
udev,,"GPLv2.0+, LGPL-2.1+"
```


#### Excluding Packages

In some cases, a more condensed CVE Report may be desired, so a list of
specific packages to omit may be specified (for example: packages that only
install data files).

To exclude packages from the CVE Report, the Kconfig option
```BR2_EXTERNAL_VIGILES_EXCLUDE_CSV``` may be set to the path of CSV file.

>Example: ```$(HOME)/projects/buildroot/vigiles-exclude-packages.csv```

The CSV file expects one package name per line. Any additional CSV fields are
ignored.

For example:

```sh
$ cat $HOME/projects/buildroot/vigiles-exclude-packages.csv
linux-libc-headers
opkg-utils
packagegroup-core-boot
```


#### Whitelisting CVEs

Some packages may have CVEs associated with them that are known to not affect
a particular machine or configuration. Buildroot packages may express these
in their respective Makefiles via the ```IGNORE_CVES``` variable. However,
there may be additional CVEs to ignore/whitelist.

A user may set the Kconfig option ```BR2_EXTERNAL_VIGILES_WHITELIST_CSV``` to
the path of a CSV file containing a list of CVEs to omit from the Vigiles
Report.

>Example: ```$(HOME)/projects/buildroot/vigiles-cve-whitelist.csv```

The CSV expects one CVE ID per line. Any additional fields will be ignored.

For example:

```sh
$ cat $HOME/projects/buildroot/vigiles-cve-whitelist.csv

```

### Uploading the Manifest (Only)

In some cases, it may be desired to upload the Vigiles Manifest for a build
without generating a CVE Report. This can speed up build times and ease
reporting of automated bulk builds.

This behavior can be enabled with the Kconfig option
```BR2_EXTERNAL_VIGILES_UPLOAD_ONLY```.

Instead of a text report and a link to the online report, a link to the
Vigiles Dashboard Product Workspace (as specified with
VIGILES_DASHBOARD_CONFIG) will be displayed, from where it can be then be
scanned by the Vigiles Service.



### LinuxLink Credentials

To specify an alternative location for the Timesys LinuxLink Key File, (default: 
```$(HOME)/timesys/linuxlink_key```) it can be set with the string
**```BR2_EXTERNAL_VIGILES_KEY_FILE```**.


```
               *** Timesys LinuxLink Account Options ***
        ($(HOME)/timesys/linuxlink_key) Timesys LinuxLink Key Location
```

>Whether the default is used, or if this Kconfig option is set, it will be
>overridden by the environment variable VIGILES_KEY_FILE.
>A developer may set this on the command line to use a personal/local key
>without having to change a shared defconfig for a board.



### Vigiles Dashboard Configuration

A custom LinuxLink Dashboard configuration can be set by first
enabling **```VIGILES_ENABLE_DASHBOARD_CONFIG```** and specifying the path in
the string **```BR2_EXTERNAL_VIGILES_DASHBOARD_CONFIG```**. If unset, a default
path will be used (```$(HOME)/timesys/dashboard_config```)

```
                *** Timesys Vigiles Dashboard Options ***
         [*]   Use a custom Vigiles Dashboard Configuration
         ($(HOME)/timesys/dashboard_config) Timesys Vigiles Dashboard Config Location
```

>Whether the default is used, or if this Kconfig option is set, it will be
>overridden by the environment variable VIGILES_DASHBOARD_CONFIG.
>A developer may set this on the command line to use their personal/private
>Dashboard settings.


By default your manifest will be uploaded to your "Private Workspace" Product
on the Vigiles Dashboard. This can be changed by downloading the "Dashboard
Config" for an alternative Product and/or Folder.

Dashboard Config files will be downloaded by default to e.g.
```"${HOME}/Downloads/<product name>_<folder name>_config"```. Once moving and/or renaming it as
necessary, you can control the behavior of Vigiles for Buildroot by setting
the config variable above.

>New Products can be defined by clicking on the "New Product" product link and specifying a name. To download the Dashboard Config for the top-level folder of that Product, click on the "Product Settings" link and you will see a preview of the dashboard config file. You can copy the contents and create the file for yourself or choose to download it with the buttons on the right.

>Once a new product is created, sub-folders may be created by clicking on the "Create Folder" and specifying a name. The Dashboard Config for that  Folder (in that Product) may be downloaded by first clicking on/opening the Folder, then clicking the "Folder Settings" link and choosing to copy or download the config for that folder.

### Dynamic subfolder creation
```
               --- Enable Timesys Vigiles CVE Check
               *** Vigiles Kernel CVE Reporting Options ***
               *** Customizing / Amending Vigiles Report ***
         ()    Custom Manifest and Report Name
         ()    Subfolder name
```

If a Dashboard Config is used, a subfolder name can be specified for dynamic folder creation. Manifests will be uploaded to a subfolder with this name within the location specified in the Dashbord Config. If one does not exist, it will be created. This option will be overridden by the environment variable ```VIGILES_SUBFOLDER_NAME```



### Advanced Options

For development purposes, some "Expert" options are available by first enabling
**```VIGILES_ENABLE_EXPERT```**. These allow for debugging of the metadata that
is collected.

These features are not supported and no documentation is provided for them.


```
               *** Advanced Vigiles / Debug Options ***
        [*]   Enable Vigiles Advanced and Debugging Options (Expert)
        [ ]   Enable Verbose Console Output
        [ ]     Write Intermediate JSON Files of Collected Metadata
        [ ]   Include virtual packages in SBOM
        [ ]   Generate SBOM only (NEW)
```

### Including Virtual Packages in generated SBOM

This option can be found under Advanced Vigiles option

```
                *** Advanced Vigiles / Debug Options ***
        [ ]   Include virtual packages in SBOM
```
This option will include the virtual packages in generated SBOM. By default vigiles-buildroot
will exclude the virtual packages from generated SBOM.

### Generating SBOM only

This option can be found under the Advanced Vigiles option

```
                *** Advanced Vigiles / Debug Options ***
        [ ]   Generate SBOM only
```
This option will only generate the SBOM. By default the generated SBOM is also
uploaded to vigiles for a vulnerability scan.
Set an environment variable GENERATE_SBOM_ONLY=True to override the setting in menuconfig.

### Other Notes

#### Make 4.3 Workaround

The version of ```make``` that was shipped with Ubuntu 22.04 contains a bug
that is described here:

>https://savannah.gnu.org/bugs/?59093

It is discussed in this Buildroot thread:

>https://git.buildroot.org/buildroot/commit/?id=5a9504831f3fa1ef3be334036c93da30150fde55

Unfortunately, this prevents Vigiles-Buildroot from working as it inherently depends on
the ```make printvars``` command.

---

In order to enable Vigiles functionality, we had to engage a very 'special' strategy
if and only if Make 4.3 is detected by which (a) we inhibit the Buildroot workaround
(by using a fixed-up top-level Makefile **ONLY FOR THAT CALL**); and (b) execute
```make printvars``` with an increased process stack size (by wrapping it with
```prlimit```)

Should this interfere with one's build system, an alternative approach can be used, though
it will require custom modifications to both vigiles-buildroot and Buildroot itself.

- Revert the vigiles-buildroot commit

- Revert the Buildroot workaround (25cec5ea733251eb)

- Increase the per-process stack size with ```ulimit``` before building.

Please note that this approach is not officially supported and YMMV.


---


#### Package Version Information in Generated SBOM

Buildroot includes packages/config scripts lacking version information (Ex. initscripts, urandom-scripts, etc.). 
In the generated SBOM for such packages version is set to the Buildroot version or the Buildroot commit hash.


#### Setting CPE ID variables 

Buildroot allows to define a set of variables in package's makefile
(`<package-name>.mk`), to specify its CPE identifier.
For instance, in the case of the busybox package, these variables such as product, version, vendor, etc. can be set in busybox.mk as below

<pre>
BUSYBOX_CPE_ID_PRODUCT = busybox
BUSYBOX_CPE_ID_VERSION = 1.36.1
BUSYBOX_CPE_ID_VENDOR = busybox
</pre>

The vigiles-buildroot uses these variables to generate a cpe id if it is not already specified


Maintenance
===========

The Vigiles CVE Scanner and Buildroot support are maintained by
[The Timesys Security team](mailto:vigiles@timesys.com).

For Updates, Support and More Information, please see:

[Vigiles Website](https://www.timesys.com/security/vigiles/)

and

[vigiles-buildroot @ GitHub](https://github.com/TimesysGit/vigiles-buildroot)
