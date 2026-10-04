package com.dimma.fileicons;

import com.intellij.psi.tree.IElementType;
import com.intellij.psi.TokenType;

public final class DimmaTokenTypes {
    public static final IElementType COMMAND = new IElementType("DIMMA_COMMAND", DimmaLanguage.INSTANCE);
    public static final IElementType AT = new IElementType("DIMMA_AT", DimmaLanguage.INSTANCE);
    public static final IElementType COLON = new IElementType("DIMMA_COLON", DimmaLanguage.INSTANCE);
    public static final IElementType BOOLEAN = new IElementType("DIMMA_BOOLEAN", DimmaLanguage.INSTANCE);
    public static final IElementType NUMBER = new IElementType("DIMMA_NUMBER", DimmaLanguage.INSTANCE);
    public static final IElementType STRING = new IElementType("DIMMA_STRING", DimmaLanguage.INSTANCE);
    public static final IElementType VALUE = new IElementType("DIMMA_VALUE", DimmaLanguage.INSTANCE);
    public static final IElementType BRACKET = new IElementType("DIMMA_BRACKET", DimmaLanguage.INSTANCE);
    public static final IElementType COMMA = new IElementType("DIMMA_COMMA", DimmaLanguage.INSTANCE);
    public static final IElementType COMMENT = new IElementType("DIMMA_COMMENT", DimmaLanguage.INSTANCE);
    public static final IElementType WHITE_SPACE = TokenType.WHITE_SPACE;
    public static final IElementType BAD_CHARACTER = TokenType.BAD_CHARACTER;

    private DimmaTokenTypes() {
    }
}
