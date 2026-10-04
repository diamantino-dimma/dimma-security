package com.dimma.fileicons;

import com.intellij.lexer.LexerBase;
import com.intellij.psi.tree.IElementType;

public final class DimmaLexer extends LexerBase {
    private CharSequence buffer = "";
    private int bufferEnd;
    private int tokenStart;
    private int tokenEnd;
    private IElementType tokenType;
    private boolean commandExpected;
    private boolean valueStarted;

    @Override
    public void start(CharSequence buffer, int startOffset, int endOffset, int initialState) {
        this.buffer = buffer;
        this.bufferEnd = endOffset;
        this.tokenStart = startOffset;
        this.tokenEnd = startOffset;
        this.commandExpected = (initialState & 1) != 0;
        this.valueStarted = (initialState & 2) != 0;
        advance();
    }

    @Override
    public int getState() {
        return (commandExpected ? 1 : 0) | (valueStarted ? 2 : 0);
    }

    @Override
    public IElementType getTokenType() {
        return tokenType;
    }

    @Override
    public int getTokenStart() {
        return tokenStart;
    }

    @Override
    public int getTokenEnd() {
        return tokenEnd;
    }

    @Override
    public void advance() {
        tokenStart = tokenEnd;
        if (tokenStart >= bufferEnd) {
            tokenType = null;
            return;
        }

        char current = buffer.charAt(tokenStart);
        if (Character.isWhitespace(current)) {
            tokenType = DimmaTokenTypes.WHITE_SPACE;
            tokenEnd = tokenStart + 1;
            while (tokenEnd < bufferEnd && Character.isWhitespace(buffer.charAt(tokenEnd))) {
                tokenEnd++;
            }
            for (int index = tokenStart; index < tokenEnd; index++) {
                char whitespace = buffer.charAt(index);
                if (whitespace == '\r' || whitespace == '\n') {
                    commandExpected = false;
                    valueStarted = false;
                }
            }
            return;
        }

        tokenEnd = tokenStart + 1;
        switch (current) {
            case '#':
                if (isCommentStart(tokenStart)) {
                    tokenType = DimmaTokenTypes.COMMENT;
                    while (tokenEnd < bufferEnd && buffer.charAt(tokenEnd) != '\r' &&
                           buffer.charAt(tokenEnd) != '\n') {
                        tokenEnd++;
                    }
                    return;
                }
                tokenType = DimmaTokenTypes.VALUE;
                while (tokenEnd < bufferEnd && !isDelimiter(buffer.charAt(tokenEnd))) {
                    tokenEnd++;
                }
                return;
            case '@':
                if (isDirectiveStart(tokenStart)) {
                    tokenType = DimmaTokenTypes.AT;
                    commandExpected = true;
                    valueStarted = false;
                } else {
                    tokenType = DimmaTokenTypes.VALUE;
                    while (tokenEnd < bufferEnd && !isDelimiter(buffer.charAt(tokenEnd))) {
                        tokenEnd++;
                    }
                }
                return;
            case ':':
                if (valueStarted) {
                    tokenType = DimmaTokenTypes.VALUE;
                    while (tokenEnd < bufferEnd && !isDelimiter(buffer.charAt(tokenEnd))) {
                        tokenEnd++;
                    }
                } else {
                    tokenType = DimmaTokenTypes.COLON;
                    commandExpected = false;
                    valueStarted = true;
                }
                return;
            case '[':
            case ']':
                tokenType = DimmaTokenTypes.BRACKET;
                return;
            case ',':
                tokenType = DimmaTokenTypes.COMMA;
                return;
            case '"':
            case '\'':
                tokenType = DimmaTokenTypes.STRING;
                while (tokenEnd < bufferEnd) {
                    char next = buffer.charAt(tokenEnd++);
                    if (next == '\\' && tokenEnd < bufferEnd) {
                        tokenEnd++;
                    } else if (next == current || next == '\r' || next == '\n') {
                        break;
                    }
                }
                return;
            default:
                break;
        }

        if (commandExpected) {
            tokenType = DimmaTokenTypes.COMMAND;
            while (tokenEnd < bufferEnd && buffer.charAt(tokenEnd) != ':' &&
                   buffer.charAt(tokenEnd) != '\r' && buffer.charAt(tokenEnd) != '\n') {
                tokenEnd++;
            }
            while (tokenEnd > tokenStart && Character.isWhitespace(buffer.charAt(tokenEnd - 1))) {
                tokenEnd--;
            }
            commandExpected = false;
            return;
        }

        while (tokenEnd < bufferEnd && !isDelimiter(buffer.charAt(tokenEnd))) {
            tokenEnd++;
        }
        String text = buffer.subSequence(tokenStart, tokenEnd).toString();
        if ("true".equals(text) || "false".equals(text)) {
            tokenType = DimmaTokenTypes.BOOLEAN;
        } else if (isNumber(text)) {
            tokenType = DimmaTokenTypes.NUMBER;
        } else {
            tokenType = DimmaTokenTypes.VALUE;
        }
    }

    @Override
    public CharSequence getBufferSequence() {
        return buffer;
    }

    @Override
    public int getBufferEnd() {
        return bufferEnd;
    }

    private static boolean isDelimiter(char value) {
        return Character.isWhitespace(value) || value == ':' || value == '[' || value == ']' ||
               value == ',' || value == '"' || value == '\'';
    }

    private boolean isCommentStart(int offset) {
        return isLineStartAfterWhitespace(offset);
    }

    private boolean isDirectiveStart(int offset) {
        return isLineStartAfterWhitespace(offset);
    }

    private boolean isLineStartAfterWhitespace(int offset) {
        int lineStart = offset - 1;
        while (lineStart >= 0 && buffer.charAt(lineStart) != '\r' && buffer.charAt(lineStart) != '\n') {
            lineStart--;
        }
        for (int index = lineStart + 1; index < offset; index++) {
            if (!Character.isWhitespace(buffer.charAt(index))) {
                return false;
            }
        }
        return true;
    }

    private static boolean isNumber(String value) {
        if (value.isEmpty()) {
            return false;
        }
        boolean decimalPoint = false;
        for (int index = 0; index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '.' && !decimalPoint) {
                decimalPoint = true;
            } else if (!Character.isDigit(character)) {
                return false;
            }
        }
        return true;
    }

}
