package com.dimma.fileicons;

import com.intellij.lang.SyntaxHighlighterBase;
import com.intellij.openapi.editor.DefaultLanguageHighlighterColors;
import com.intellij.openapi.editor.HighlighterColors;
import com.intellij.openapi.editor.colors.TextAttributesKey;
import com.intellij.psi.tree.IElementType;
import org.jetbrains.annotations.NotNull;

import static com.dimma.fileicons.DimmaTokenTypes.*;

public final class DimmaSyntaxHighlighter extends SyntaxHighlighterBase {
    public static final TextAttributesKey COMMAND_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_COMMAND", DefaultLanguageHighlighterColors.KEYWORD);
    public static final TextAttributesKey COMMENT_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_COMMENT", DefaultLanguageHighlighterColors.LINE_COMMENT);
    public static final TextAttributesKey BOOLEAN_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_BOOLEAN", DefaultLanguageHighlighterColors.CONSTANT);
    public static final TextAttributesKey NUMBER_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_NUMBER", DefaultLanguageHighlighterColors.NUMBER);
    public static final TextAttributesKey STRING_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_STRING", DefaultLanguageHighlighterColors.STRING);
    public static final TextAttributesKey VALUE_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_VALUE", DefaultLanguageHighlighterColors.IDENTIFIER);
    public static final TextAttributesKey BRACKET_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_BRACKET", DefaultLanguageHighlighterColors.BRACKETS);
    public static final TextAttributesKey COMMA_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_COMMA", DefaultLanguageHighlighterColors.COMMA);
    public static final TextAttributesKey COLON_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_COLON", DefaultLanguageHighlighterColors.OPERATION_SIGN);
    public static final TextAttributesKey BAD_CHARACTER_KEY =
            TextAttributesKey.createTextAttributesKey("DIMMA_BAD_CHARACTER", HighlighterColors.BAD_CHARACTER);

    @Override
    public @NotNull com.intellij.lexer.Lexer getHighlightingLexer() {
        return new DimmaLexer();
    }

    @Override
    public TextAttributesKey @NotNull [] getTokenHighlights(IElementType tokenType) {
        if (tokenType == COMMAND) return pack(COMMAND_KEY);
        if (tokenType == COMMENT) return pack(COMMENT_KEY);
        if (tokenType == BOOLEAN) return pack(BOOLEAN_KEY);
        if (tokenType == NUMBER) return pack(NUMBER_KEY);
        if (tokenType == STRING) return pack(STRING_KEY);
        if (tokenType == VALUE) return pack(VALUE_KEY);
        if (tokenType == BRACKET) return pack(BRACKET_KEY);
        if (tokenType == COMMA) return pack(COMMA_KEY);
        if (tokenType == COLON || tokenType == AT) return pack(COLON_KEY);
        if (tokenType == BAD_CHARACTER) return pack(BAD_CHARACTER_KEY);
        return TextAttributesKey.EMPTY_ARRAY;
    }
}
