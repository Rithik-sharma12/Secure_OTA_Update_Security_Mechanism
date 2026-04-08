# Terminal & Coding Environment

## Overview
The OTA IDE now includes an integrated terminal and code editor for managing firmware builds, executing commands, and editing configuration files directly from the web interface.

## Components Added

### 1. Terminal Component (`components/terminal/Terminal.tsx`)
A fully functional terminal interface with:
- **Command Execution**: Execute OTA CLI commands
- **Command History**: View previously executed commands with status indicators
- **Output Display**: Real-time command output with syntax-aware coloring
- **Status Indicators**: Visual feedback for success, error, and pending states
- **Mock Commands Supported**:
  - `help` - Display available commands
  - `build` - Compile firmware
  - `status` - Show device status
  - `version` - Display OTA IDE version
  - `clear` - Clear terminal output

### 2. Code Editor Component (`components/editor/CodeEditor.tsx`)
A comprehensive code editor with:
- **Syntax Support**: JSON, C, Python, JavaScript, XML
- **Line Numbers**: Visual line numbering for easy reference
- **Preview Mode**: Toggle between edit and preview views
- **Copy Function**: Copy code to clipboard
- **Save Functionality**: Save edited code with confirmation
- **Character & Line Count**: Real-time statistics
- **Read-only Mode**: Optional read-only viewing of code

### 3. Terminal & Coding Page (`app/(dashboard)/terminal/page.tsx`)
Main page combining both components with:
- **Integrated Terminal**: Open terminal in a floating modal
- **Code Editor Modal**: Edit files in a full-screen editor
- **File Browser**: View and manage project code files
- **Quick Actions**: Quick buttons for common operations
- **File Information**: Display file metadata and language

## Navigation

The Terminal & Coding environment is accessible from the sidebar under the **Deploy** section:
- Click **Terminal** in the left sidebar
- Or navigate to `/dashboard/terminal`

## Features

### Terminal Features
- **Command Autocomplete**: Type `help` to see all available commands
- **Mock Command Responses**: Realistic simulated outputs
- **Floating Panel**: Terminal opens as a floating panel on the right
- **Clearing**: Clear terminal history with one click
- **Execution Feedback**: Visual indicators for command status

### Code Editor Features
- **Multi-language Support**: Edit firmware configs, C code, manifests, etc.
- **Smart Display**: Automatic language detection and syntax highlighting
- **File Management**: Switch between multiple project files
- **Download Export**: Export edited files to your computer
- **Status Tracking**: See when files were last modified

### Project Files
Three sample files included:
1. **firmware-config.json** - Build configuration with optimization settings
2. **device-bootstrap.c** - C code for device initialization
3. **deployment-manifest.xml** - XML manifest for deployment configuration

## Usage Examples

### Building Firmware
```bash
$ ota-cli build --target esp32
Building firmware for ESP32...
Compiling source files...
✓ Build complete: 245.3 KB
✓ Checksum: a1b2c3d4e5f6g7h8
```

### Checking Device Status
```bash
$ status
Device Status:
✓ ESP32-Dev-01: Online (v2.4.0)
✓ ESP8266-Test-01: Online (v2.3.1)
✗ ATmega-Prod-01: Offline
✓ STM32-Beta-01: Online (v2.5.0-rc1)
```

### Editing Configuration Files
1. Select a file from the Project Files list
2. Click "Edit" or "Open Editor"
3. Make changes in the editor modal
4. Click "Save" to persist changes
5. Click "Download" to export the file

## Technical Details

### Terminal Command Processing
Commands are processed through a mock execution system that simulates actual OTA CLI behavior:
- Commands are parsed and matched against supported operations
- Output is generated based on the command type
- Status indicators show success/error/pending states
- All output is stored in command history

### Code Editor State Management
- Selected file is tracked in component state
- Changes are only persisted when "Save" is clicked
- Files can be edited and downloaded independently
- Line count updates in real-time as you type

### Styling
- OTA IDE theme colors applied throughout
- Dark mode optimized with glass-morphism effects
- Responsive design adapts to different screen sizes
- Smooth transitions and hover effects

## Integration with Other Features

The terminal and code editor integrate seamlessly with:
- **Manifest Management**: Edit manifests directly from the editor
- **Release Pipeline**: Execute build commands from the terminal
- **Device Management**: Check device status and deploy from terminal
- **Settings & Config**: Modify configuration files and save immediately

## Future Enhancements

Potential additions to the terminal and code editor:
- Real-time syntax validation
- Code completion with IntelliSense
- Integrated debugging console
- File diff viewer for version comparisons
- Command suggestions and history search
- Theme customization for editor
- Plugin/extension support
- Real WebSocket connection to actual backend CLI

## File Structure
```
components/
├── terminal/
│   └── Terminal.tsx          # Terminal interface
└── editor/
    └── CodeEditor.tsx        # Code editor component

app/(dashboard)/
└── terminal/
    └── page.tsx              # Terminal & coding main page
```
