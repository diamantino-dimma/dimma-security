# Dimma File Icons for JetBrains IDEs

This IntelliJ Platform plugin registers `.dimma` files, including
`security.dimma`, as plain-text Dimma configuration files and uses the project
shield icon.

## Build and install locally

Requirements: JDK 17 and Gradle. The IntelliJ Platform Gradle Plugin downloads
the IntelliJ IDEA Community build configured in `build.gradle.kts`.

```powershell
gradle buildPlugin
```

The installable ZIP is written to `build\distributions\`. In IntelliJ IDEA,
open **Settings | Plugins**, select the gear menu, choose **Install Plugin
from Disk...**, and select the ZIP. Restart the IDE if prompted, then confirm
the icon on `security.dimma` and another `.dimma` file.

To run a development IDE with the plugin loaded, use:

```powershell
gradle runIde
```

## Publish

Before publishing, confirm that `com.dimma.fileicons` is available, replace
the vendor placeholder if needed, test the ZIP in each supported JetBrains
IDE, and follow the JetBrains Marketplace plugin publishing process. Do not
publish until the project owner has confirmed the applicable rights to the
name, code, and icon.

This plugin provides file-type recognition and an icon only. It does not add
syntax highlighting, validation, or security enforcement.
