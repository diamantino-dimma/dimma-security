package com.dimma.fileicons;

import com.intellij.openapi.editor.colors.TextAttributesKey;
import com.intellij.openapi.fileTypes.SyntaxHighlighter;
import com.intellij.openapi.options.colors.AttributesDescriptor;
import com.intellij.openapi.options.colors.ColorDescriptor;
import com.intellij.openapi.options.colors.ColorSettingsPage;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.Icon;
import java.util.Map;

public final class DimmaColorSettingsPage implements ColorSettingsPage {
    private static final AttributesDescriptor[] DESCRIPTORS = {
            new AttributesDescriptor("Directive", DimmaSyntaxHighlighter.COMMAND_KEY),
            new AttributesDescriptor("Comment", DimmaSyntaxHighlighter.COMMENT_KEY),
            new AttributesDescriptor("Boolean", DimmaSyntaxHighlighter.BOOLEAN_KEY),
            new AttributesDescriptor("Number", DimmaSyntaxHighlighter.NUMBER_KEY),
            new AttributesDescriptor("String", DimmaSyntaxHighlighter.STRING_KEY),
            new AttributesDescriptor("Value", DimmaSyntaxHighlighter.VALUE_KEY),
            new AttributesDescriptor("List brackets", DimmaSyntaxHighlighter.BRACKET_KEY),
            new AttributesDescriptor("List comma", DimmaSyntaxHighlighter.COMMA_KEY),
            new AttributesDescriptor("Separators", DimmaSyntaxHighlighter.COLON_KEY)
    };

    @Override
    public @Nullable Icon getIcon() {
        return DimmaFileType.INSTANCE.getIcon();
    }

    @Override
    public @NotNull SyntaxHighlighter getHighlighter() {
        return new DimmaSyntaxHighlighter();
    }

    @Override
    public @NotNull String getDemoText() {
        return "# Dimma security configuration\n" +
               "@auto_protect: <boolean>true</boolean>\n" +
               "@protect input: <bracket>[</bracket><value>sql_injection</value><comma>,</comma> <value>xss</value><bracket>]</bracket>\n" +
               "@rate_limit: <number>100</number> <value>req/min</value>\n" +
               "@csrf_protection: <boolean>true</boolean>\n" +
               "@ai_provider: <value>nvidia</value>\n" +
               "@exclude: <value>/health</value>\n";
    }

    @Override
    public @Nullable Map<String, TextAttributesKey> getAdditionalHighlightingTagToDescriptorMap() {
        return Map.of(
                "boolean", DimmaSyntaxHighlighter.BOOLEAN_KEY,
                "number", DimmaSyntaxHighlighter.NUMBER_KEY,
                "value", DimmaSyntaxHighlighter.VALUE_KEY,
                "bracket", DimmaSyntaxHighlighter.BRACKET_KEY,
                "comma", DimmaSyntaxHighlighter.COMMA_KEY
        );
    }

    @Override
    public AttributesDescriptor @NotNull [] getAttributeDescriptors() {
        return DESCRIPTORS;
    }

    @Override
    public @NotNull String getDisplayName() {
        return "Dimma";
    }

    @Override
    public ColorDescriptor @NotNull [] getColorDescriptors() {
        return ColorDescriptor.EMPTY_ARRAY;
    }
}
