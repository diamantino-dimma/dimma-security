package com.dimma.fileicons;

import com.intellij.lang.Language;

public final class DimmaLanguage extends Language {
    public static final DimmaLanguage INSTANCE = new DimmaLanguage();

    private DimmaLanguage() {
        super("Dimma");
    }
}
