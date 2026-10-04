# Dimma File Icons and Syntax for VS Code and Cursor

Adds the Dimma shield icon and syntax highlighting to `.dimma` files,
including `security.dimma`. Directives, comments, strings, booleans, numbers,
list delimiters, and values receive separate TextMate scopes. Their displayed
colors follow the user's active VS Code color theme.
Cursor uses Open VSX for third-party extensions, so publish this same VSIX
there if you want Cursor users to find it in the Extensions panel.

The Python and Node.js packages both bundle this VSIX. After installing either,
run `dimma styles`. It installs the VSIX into each detected VS Code, Cursor,
and VSCodium CLI. It does not read or modify workspace settings, so your
existing file icon theme remains active. The language association and syntax
highlighting apply only to `.dimma` files. It never runs as a package install
hook.

## Install from a VSIX

1. Download the `.vsix` release asset.
2. In VS Code, run **Extensions: Install from VSIX...** from the Command
   Palette and select the downloaded file.
3. Run **Preferences: File Icon Theme** and select **Dimma File Icons**.

The extension contributes syntax highlighting independently of the selected
icon theme. Selecting **Dimma File Icons** manually changes the active file
icon theme for the editor. VS Code does not support layering file icon themes
or applying them to only one extension, so `dimma styles` installs the
language extension but does not select its icon theme.

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
