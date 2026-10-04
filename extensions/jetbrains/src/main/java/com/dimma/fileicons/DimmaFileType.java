package com.dimma.fileicons;

import com.intellij.openapi.fileTypes.LanguageFileType;
import com.intellij.openapi.fileTypes.PlainTextLanguage;
import com.intellij.openapi.util.IconLoader;
import org.jetbrains.annotations.NotNull;

import javax.swing.Icon;

public final class DimmaFileType extends LanguageFileType {
    public static final DimmaFileType INSTANCE = new DimmaFileType();

    private DimmaFileType() {
        super(PlainTextLanguage.INSTANCE);
    }

    @Override
    public @NotNull String getName() {
        return "Dimma";
    }

    @Override
    public @NotNull String getDescription() {
        return "Dimma security configuration";
    }

    @Override
    public @NotNull String getDefaultExtension() {
        return "dimma";
    }

    @Override
    public Icon getIcon() {
        return IconLoader.getIcon("/icons/dimma-file-icon.svg", DimmaFileType.class);
    }
}
