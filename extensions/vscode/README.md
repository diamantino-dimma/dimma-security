# Dimma File Icons for VS Code and Cursor

Adds the Dimma shield icon to files with the `.dimma` extension, including
`security.dimma`.
Cursor uses Open VSX for third-party extensions, so publish this same VSIX
there if you want Cursor users to find it in the Extensions panel.

## Install from a VSIX

1. Download the `.vsix` release asset.
2. In VS Code, run **Extensions: Install from VSIX...** from the Command
   Palette and select the downloaded file.
3. Run **Preferences: File Icon Theme** and select **Dimma File Icons**.

This is a standalone icon theme. Selecting it changes the active file icon
theme; installing `dimma-core` or `dimma` alone cannot change an editor's
icons.

## Package locally

Replace `your-publisher-id` in `package.json` with the publisher ID of your
Visual Studio Marketplace account, then run:

```powershell
npx --yes @vscode/vsce package
```

To publish it to the Marketplace, first create and verify the publisher at
Visual Studio Marketplace, authenticate `vsce`, then run `vsce publish`.

To distribute it for Cursor, create a publisher on
[Open VSX](https://open-vsx.org/), build the VSIX above, and upload that VSIX
to the Open VSX publisher portal. Cursor users can then search for **Dimma
File Icons** in Extensions. Publishing to the Visual Studio Marketplace alone
does not guarantee availability in Cursor.

IntelliJ-based IDEs use the separate plugin in `../jetbrains/`. Visual Studio
(the full IDE, not VS Code) requires its own extension and is not supported by
this theme.
