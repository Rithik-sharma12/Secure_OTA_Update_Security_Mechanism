# VSCode-Style Code Editor Guide

## Overview

The **Code Editor** in OTA IDE is a full-featured, VSCode and Arduino IDE-inspired development environment with complete CRUD operations for firmware development.

## Features

### 1. File Management (Left Sidebar - "Code")

#### Create New File
- Click the **+** button in the Code sidebar header
- Enter file name and select language
- Supported languages:
  - **JSON** - Configuration files (.json)
  - **C** - Embedded C code (.c)
  - **C++** - C++ code (.cpp)
  - **Header** - C/C++ headers (.h)
  - **Python** - Python scripts (.py)
  - **JavaScript** - JS files (.js)
  - **XML** - Markup files (.xml)
- File is created and opened in the editor automatically

#### Read Files
- Browse all project files in the "Code" sidebar
- Click any file to view its contents
- Files show syntax highlighting by language
- Display total lines and last modified timestamp

#### Update Files
- Click **Edit** button to enter edit mode
- Make changes in the code editor
- Line numbers appear automatically
- Unsaved changes are indicated with a yellow dot (●)
- Click **Save** to persist changes or **Cancel** to discard

#### Delete Files
- Hover over a file in the sidebar
- Click the trash icon (🗑)
- Confirm deletion in the dialog
- File is removed from the project

### 2. Code Editor (Main Panel)

#### Edit Mode
- **Enter Edit Mode**: Click the "Edit" button
- Full textarea editor with line numbers
- Auto-indentation and syntax awareness
- Real-time unsaved indicator
- **Save**: Persists changes to the file
- **Cancel**: Discards edits

#### Read Mode
- Default view when file is selected
- Line-by-line syntax highlighting
- Code is read-only, click "Edit" to modify
- Perfect for code review

### 3. File Operations

#### File Header Information
Shows when a file is selected:
- File name with unsaved indicator
- Language badge (color-coded)
- Line count
- Last modified timestamp

#### Quick Actions (Right Side)
- **Edit**: Switch to edit mode
- **Copy**: Copy entire file content to clipboard
- **Download**: Download file to your computer
- **Save/Cancel**: When in edit mode

### 4. File Rename
- Hover over a file in the sidebar
- Click the edit icon (✏️)
- Type new name
- Press Enter to confirm or Escape to cancel

### 5. Terminal Integration
- Built-in terminal at the bottom
- Toggle on/off with the button in the Terminal section
- Execute OTA CLI commands
- Includes:
  - `build` - Build firmware
  - `status` - Check device status
  - `deploy` - Deploy firmware
  - `version` - Show version info
  - And more...

## Supported File Types

| Language | Extension | Use Case |
|----------|-----------|----------|
| JSON | .json | Configuration & manifests |
| C | .c | Embedded firmware code |
| C++ | .cpp | Advanced embedded systems |
| Header | .h | C/C++ header files |
| Python | .py | Build scripts & tools |
| JavaScript | .js | Build automation |
| XML | .xml | Deployment manifests |

## Keyboard Shortcuts

- **Edit Mode**:
  - `Ctrl+Enter` / `Cmd+Enter` - Save (click button)
  - `Escape` - Close without saving
  - `Tab` - Indent
  - `Shift+Tab` - Outdent

## Color Theme

The editor maintains the OTA IDE's dark theme:
- **Primary**: Deep purple/violet (#854f6c)
- **Background**: Very dark purple (#0f0a12)
- **Accent**: Soft cream (#fbe4d8)
- **Success**: Green (#10b981)
- **Danger**: Red (#ff6b6b)

## Example Workflow

1. **Create a new firmware config**
   - Click "+" in Code sidebar
   - Name: `firmware-v3.json`
   - Language: JSON
   - Start coding your configuration

2. **Edit existing files**
   - Select file from sidebar
   - Click "Edit"
   - Make your changes
   - Click "Save"

3. **Download for deployment**
   - Select file
   - Click "Download"
   - File saves to your computer

4. **Use terminal for testing**
   - Click terminal toggle
   - Type: `build firmware-v3.json`
   - See output in real-time

## Best Practices

- **Save frequently** - Use the Save button to persist changes
- **Use meaningful names** - Include version/purpose in filename
- **Organize files** - Group related configs together
- **Review before delete** - Check file is not needed before removing
- **Copy code** - Use Copy button for sharing code snippets
- **Test with terminal** - Verify builds and deployments from the terminal

## Troubleshooting

**File not saving?**
- Check browser console for errors
- Ensure file name is valid
- Try refreshing the page

**Terminal not responding?**
- Toggle terminal off and on
- Check command syntax
- View error messages in terminal output

**Cannot edit file?**
- Click "Edit" button to enter edit mode
- Check file isn't corrupted
- Try refreshing the page

## Integration with Other Tools

- **Pipeline**: Deploy code directly from editor
- **Manifest Editor**: Link to manifest files
- **Terminal**: Execute builds and tests
- **Releases**: Package files for distribution

---

**Last Updated**: 2026-04-08
**Version**: 1.0
