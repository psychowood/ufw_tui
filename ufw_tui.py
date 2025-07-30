#!/usr/bin/env python3
"""
UFW TUI Manager - Text User Interface for UFW similar to Midnight Commander
Requires sudo privileges to work properly
"""

import curses
import subprocess
import re
import json
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class ViewMode(Enum):
    RULES = "rules"
    APPS = "apps" 
    LISTENING = "listening"

@dataclass
class UFWRule:
    num: str
    to: str
    action: str
    from_addr: str
    
    def __str__(self):
        return f"{self.num:>3} {self.action:<6} {self.to:<20} from {self.from_addr}"

class UFWManager:
    def __init__(self):
        self.rules: List[UFWRule] = []
        self.apps: List[str] = []
        self.listening_ports: List[Tuple[str, str, str]] = []
        self.refresh_data()
    
    def run_command(self, cmd: List[str]) -> Tuple[str, str, int]:
        """Execute a command and return output, error, return_code"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired:
            return "", "Timeout", 1
        except Exception as e:
            return "", str(e), 1
    
    def get_ufw_status(self) -> bool:
        """Check if UFW is active"""
        out, _, code = self.run_command(['sudo', 'ufw', 'status'])
        return 'Status: active' in out
    
    def get_rules(self):
        """Get UFW rules"""
        out, _, code = self.run_command(['sudo', 'ufw', 'status', 'numbered'])
        if code != 0:
            return []
        
        rules = []
        lines = out.split('\n')[4:]  # Skip header
        for line in lines:
            if line.strip() and '[' in line and ']' in line:
                # Parse line format: [ 1] 22/tcp                     ALLOW IN    Anywhere
                match = re.match(r'\s*\[\s*(\d+)\]\s+(.+?)\s+(ALLOW|DENY|REJECT)\s+(IN|OUT)\s+(.+)', line.strip())
                if match:
                    num, to, action, direction, from_addr = match.groups()
                    rules.append(UFWRule(num, f"{to} {direction}", action, from_addr))
        return rules
    
    def get_apps(self):
        """Get available applications"""
        out, _, code = self.run_command(['sudo', 'ufw', 'app', 'list'])
        if code != 0:
            return []
        
        apps = []
        for line in out.split('\n'):
            line = line.strip()
            if line and not line.startswith('Available') and line != '':
                apps.append(line)
        return apps
    
    def get_listening_ports(self):
        """Get listening ports"""
        out, _, code = self.run_command(['ss', '-tuln'])
        if code != 0:
            return []
        
        ports = []
        for line in out.split('\n')[1:]:  # Skip header
            if line.strip():
                parts = line.split()
                if len(parts) >= 5:
                    proto = parts[0]
                    state = parts[1] if len(parts) > 1 else ""
                    local = parts[4] if len(parts) > 4 else ""
                    if local and ':' in local:
                        port = local.split(':')[-1]
                        ports.append((proto, port, state))
        return ports
    
    def refresh_data(self):
        """Refresh all data"""
        self.rules = self.get_rules()
        self.apps = self.get_apps()
        self.listening_ports = self.get_listening_ports()
    
    def add_rule(self, rule: str) -> Tuple[bool, str]:
        """Add a UFW rule"""
        out, err, code = self.run_command(['sudo', 'ufw'] + rule.split())
        return code == 0, err if code != 0 else "Rule added successfully"
    
    def delete_rule(self, rule_num: str) -> Tuple[bool, str]:
        """Delete a UFW rule"""
        out, err, code = self.run_command(['sudo', 'ufw', 'delete', rule_num])
        return code == 0, err if code != 0 else "Rule deleted successfully"
    
    def toggle_ufw(self) -> Tuple[bool, str]:
        """Enable/disable UFW"""
        if self.get_ufw_status():
            out, err, code = self.run_command(['sudo', 'ufw', 'disable'])
            return code == 0, err if code != 0 else "UFW disabled"
        else:
            out, err, code = self.run_command(['sudo', 'ufw', 'enable'])
            return code == 0, err if code != 0 else "UFW enabled"

class UFWTUI:
    def __init__(self):
        self.ufw = UFWManager()
        self.current_view = ViewMode.RULES
        self.selected_left = 0
        self.selected_right = 0
        self.focus_left = True  # True: left panel, False: right panel
        self.message = ""
        self.message_time = 0
        
        # Left panel commands
        self.left_commands = [
            ("Add ALLOW rule", self.add_allow_rule),
            ("Add DENY rule", self.add_deny_rule),
            ("Delete rule", self.delete_selected_rule),
            ("", None),  # Separator
            ("Enable/Disable UFW", self.toggle_firewall),
            ("Reset UFW", self.reset_firewall),
            ("", None),  # Separator
            ("View: Rules", lambda: self.change_view(ViewMode.RULES)),
            ("View: Applications", lambda: self.change_view(ViewMode.APPS)),
            ("View: Listening ports", lambda: self.change_view(ViewMode.LISTENING)),
            ("", None),  # Separator
            ("Refresh data", self.refresh),
            ("Exit", self.quit_app),
        ]
    
    def run(self, stdscr):
        """Main application loop"""
        self.stdscr = stdscr
        curses.curs_set(0)  # Hide cursor
        curses.start_color()
        curses.use_default_colors()
        
        # Define colors
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)    # Header
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_CYAN)    # Selection
        curses.init_pair(3, curses.COLOR_RED, -1)                     # Error
        curses.init_pair(4, curses.COLOR_GREEN, -1)                   # Success
        curses.init_pair(5, curses.COLOR_YELLOW, -1)                  # Warning
        
        self.running = True
        while self.running:
            self.draw_screen()
            self.handle_input()
    
    def safe_addstr(self, win, y, x, text, attr=0):
        """Safely add string to window, handling screen boundaries"""
        try:
            max_y, max_x = win.getmaxyx()
            if y >= max_y or x >= max_x:
                return
            
            # Truncate text if it would exceed screen width
            available_width = max_x - x - 1
            if available_width <= 0:
                return
                
            safe_text = str(text)[:available_width]
            win.addstr(y, x, safe_text, attr)
        except curses.error:
            # Ignore curses errors (e.g., writing to bottom-right corner)
            pass
    
    def draw_screen(self):
        """Draw the complete interface"""
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        
        # Ensure minimum terminal size
        if height < 10 or width < 40:
            self.safe_addstr(self.stdscr, 0, 0, "Terminal too small! Min: 40x10")
            self.stdscr.refresh()
            return
        
        # Header
        status_text = 'ACTIVE' if self.ufw.get_ufw_status() else 'INACTIVE'
        header = f" UFW TUI Manager - Status: {status_text} "
        self.safe_addstr(self.stdscr, 0, 0, header.ljust(width), curses.color_pair(1))
        
        # Vertical divider
        mid_col = width // 2
        for i in range(1, height - 2):
            self.safe_addstr(self.stdscr, i, mid_col, '|')
        
        # Left panel - Commands
        self.draw_left_panel(mid_col)
        
        # Right panel - Data
        self.draw_right_panel(mid_col, width)
        
        # Footer
        footer = f" F1:Help F5:Refresh F10:Quit | View: {self.current_view.value.upper()} "
        self.safe_addstr(self.stdscr, height-1, 0, footer.ljust(width), curses.color_pair(1))
        
        # Message if present
        if self.message and height > 3:
            msg_color = curses.color_pair(4) if "success" in self.message.lower() else curses.color_pair(3)
            self.safe_addstr(self.stdscr, height-2, 2, self.message, msg_color)
        
        self.stdscr.refresh()
    
    def draw_left_panel(self, max_width):
        """Draw left panel with commands"""
        self.safe_addstr(self.stdscr, 1, 2, "COMMANDS:")
        
        y = 3
        visible_index = 0
        for i, (cmd, _) in enumerate(self.left_commands):
            if y >= curses.LINES - 3:
                break
            
            if not cmd:  # Separator
                y += 1
                continue
            
            # Highlight selection and focus
            if visible_index == self.selected_left and self.focus_left:
                self.safe_addstr(self.stdscr, y, 1, f" {cmd} ".ljust(max_width-2), curses.color_pair(2))
            else:
                self.safe_addstr(self.stdscr, y, 2, cmd)
            
            y += 1
            visible_index += 1
    
    def draw_right_panel(self, start_col, max_width):
        """Draw right panel with data"""
        start_col += 2
        width = max_width - start_col - 2
        
        if width <= 0:
            return
        
        if self.current_view == ViewMode.RULES:
            self.draw_rules_panel(start_col, width)
        elif self.current_view == ViewMode.APPS:
            self.draw_apps_panel(start_col, width)
        elif self.current_view == ViewMode.LISTENING:
            self.draw_listening_panel(start_col, width)
    
    def draw_rules_panel(self, start_col, width):
        """Draw rules panel"""
        self.safe_addstr(self.stdscr, 1, start_col, "UFW RULES:")
        
        if not self.ufw.rules:
            self.safe_addstr(self.stdscr, 3, start_col, "No rules configured")
            return
        
        y = 3
        for i, rule in enumerate(self.ufw.rules):
            if y >= curses.LINES - 3:
                break
            
            rule_text = str(rule)
            
            if i == self.selected_right and self.current_view == ViewMode.RULES and not self.focus_left:
                self.safe_addstr(self.stdscr, y, start_col-1, f" {rule_text} ".ljust(width), curses.color_pair(2))
            else:
                self.safe_addstr(self.stdscr, y, start_col, rule_text)
            y += 1
    
    def draw_apps_panel(self, start_col, width):
        """Draw applications panel"""
        self.safe_addstr(self.stdscr, 1, start_col, "APPLICATIONS:")
        
        if not self.ufw.apps:
            self.safe_addstr(self.stdscr, 3, start_col, "No applications available")
            return
        
        y = 3
        for i, app in enumerate(self.ufw.apps):
            if y >= curses.LINES - 3:
                break
            
            if i == self.selected_right and self.current_view == ViewMode.APPS and not self.focus_left:
                self.safe_addstr(self.stdscr, y, start_col-1, f" {app} ".ljust(width), curses.color_pair(2))
            else:
                self.safe_addstr(self.stdscr, y, start_col, app)
            y += 1
    
    def draw_listening_panel(self, start_col, width):
        """Draw listening ports panel"""
        self.safe_addstr(self.stdscr, 1, start_col, "LISTENING PORTS:")
        
        if not self.ufw.listening_ports:
            self.safe_addstr(self.stdscr, 3, start_col, "No listening ports")
            return
        
        y = 3
        for i, (proto, port, state) in enumerate(self.ufw.listening_ports):
            if y >= curses.LINES - 3:
                break
            
            port_text = f"{proto:<4} {port:<6} {state}"
            
            if i == self.selected_right and self.current_view == ViewMode.LISTENING and not self.focus_left:
                self.safe_addstr(self.stdscr, y, start_col-1, f" {port_text} ".ljust(width), curses.color_pair(2))
            else:
                self.safe_addstr(self.stdscr, y, start_col, port_text)
            y += 1
    
    def handle_input(self):
        """Handle user input"""
        key = self.stdscr.getch()
        
        if key == ord('q') or key == curses.KEY_F10:
            self.running = False
        elif key == curses.KEY_F5:
            self.refresh()
        elif key == curses.KEY_UP:
            if self.focus_left:
                self.move_selection(-1, left=True)
            else:
                self.move_selection(-1, left=False)
        elif key == curses.KEY_DOWN:
            if self.focus_left:
                self.move_selection(1, left=True)
            else:
                self.move_selection(1, left=False)
        elif key == curses.KEY_LEFT:
            self.focus_left = True
        elif key == curses.KEY_RIGHT:
            self.focus_left = False
        elif key == ord('\n') or key == ord('\r'):
            self.execute_selected()
        elif key == ord('1'):
            self.change_view(ViewMode.RULES)
        elif key == ord('2'):
            self.change_view(ViewMode.APPS)
        elif key == ord('3'):
            self.change_view(ViewMode.LISTENING)
    
    def move_selection(self, direction, left=True):
        """Move selection up/down in the focused panel"""
        if left:
            visible_commands = [cmd for cmd, _ in self.left_commands if cmd]
            max_left = len(visible_commands) - 1
            if max_left >= 0:
                self.selected_left = max(0, min(max_left, self.selected_left + direction))
        else:
            if self.current_view == ViewMode.RULES:
                max_right = len(self.ufw.rules) - 1
            elif self.current_view == ViewMode.APPS:
                max_right = len(self.ufw.apps) - 1
            else:
                max_right = len(self.ufw.listening_ports) - 1
            if max_right >= 0:
                self.selected_right = max(0, min(max_right, self.selected_right + direction))
    
    def execute_selected(self):
        """Execute selected command"""
        # Map selected_left to actual command index (skipping separators)
        visible_commands = [(i, cmd, func) for i, (cmd, func) in enumerate(self.left_commands) if cmd]
        
        if self.selected_left < len(visible_commands):
            _, _, func = visible_commands[self.selected_left]
            if func:
                func()
    
    def change_view(self, view_mode):
        """Change view mode"""
        self.current_view = view_mode
        self.selected_right = 0
        self.message = f"View changed: {view_mode.value}"
    
    def refresh(self):
        """Refresh data"""
        self.ufw.refresh_data()
        self.message = "Data refreshed"
    
    def add_allow_rule(self):
        """Add an ALLOW rule"""
        rule = self.get_input("Enter ALLOW rule (e.g., '22' or 'ssh'): ")
        if rule:
            success, msg = self.ufw.add_rule(f"allow {rule}")
            self.message = msg
            if success:
                self.refresh()
    
    def add_deny_rule(self):
        """Add a DENY rule"""
        rule = self.get_input("Enter DENY rule (e.g., '80' or 'from 192.168.1.0/24'): ")
        if rule:
            success, msg = self.ufw.add_rule(f"deny {rule}")
            self.message = msg
            if success:
                self.refresh()
    
    def delete_selected_rule(self):
        """Delete selected rule"""
        if (self.current_view == ViewMode.RULES and 
            self.selected_right < len(self.ufw.rules)):
            rule = self.ufw.rules[self.selected_right]
            confirm = self.get_input(f"Delete rule {rule.num}? (y/N): ")
            if confirm.lower() == 'y':
                success, msg = self.ufw.delete_rule(rule.num)
                self.message = msg
                if success:
                    self.refresh()
        else:
            self.message = "Select a rule to delete"
    
    def toggle_firewall(self):
        """Enable/disable UFW"""
        success, msg = self.ufw.toggle_ufw()
        self.message = msg
    
    def reset_firewall(self):
        """Reset UFW"""
        confirm = self.get_input("WARNING: Complete UFW reset? (y/N): ")
        if confirm.lower() == 'y':
            out, err, code = self.ufw.run_command(['sudo', 'ufw', '--force', 'reset'])
            self.message = "UFW reset" if code == 0 else f"Error: {err}"
            self.refresh()
    
    def get_input(self, prompt):
        """Show input prompt"""
        height, width = self.stdscr.getmaxyx()
        
        # Create input window
        win_width = min(60, width-4)
        win_height = 5
        win_y = max(0, (height - win_height) // 2)
        win_x = max(0, (width - win_width) // 2)
        
        try:
            input_win = curses.newwin(win_height, win_width, win_y, win_x)
            input_win.box()
            
            # Add prompt
            prompt_text = prompt[:win_width-4]
            input_win.addstr(1, 2, prompt_text)
            input_win.refresh()
            
            # Enable cursor and echo
            curses.curs_set(1)
            curses.echo()
            
            # Get input
            input_win.move(2, 2)
            user_input = input_win.getstr(2, 2, win_width-6).decode('utf-8')
            
        except Exception as e:
            user_input = ""
        finally:
            # Restore state
            curses.noecho()
            curses.curs_set(0)
            
            # Clean up
            try:
                input_win.clear()
                input_win.refresh()
                del input_win
            except:
                pass
        
        return user_input.strip()
    
    def quit_app(self):
        """Exit application"""
        self.running = False

def main():
    """Main function"""
    # Check if root or sudo is available
    try:
        result = subprocess.run(['sudo', '-n', 'true'], capture_output=True)
        if result.returncode != 0:
            print("Error: This application requires sudo privileges.")
            print("Run: sudo python3 ufw_tui.py")
            return 1
    except FileNotFoundError:
        print("Error: sudo not found on system")
        return 1
    
    # Check if UFW is installed
    try:
        subprocess.run(['which', 'ufw'], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print("Error: UFW is not installed on the system")
        return 1
    
    try:
        app = UFWTUI()
        curses.wrapper(app.run)
    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())