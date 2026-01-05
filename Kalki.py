import functools
import json
import signal
import os
import time
import sys
import random
from datetime import datetime
import platform
import shutil
# Packages 
from shutil import get_terminal_size
import pyfiglet
from colorama import init, Fore, Style, Back, Cursor
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.table import Table
from rich import box
from requests.adapters import HTTPAdapter
from urllib3 import Retry




# Modules
from Sql_injection.Static_Analysis.static_analyzer import Tokenizer, HTMLSecurityChecker, JavaScriptSecurityChecker, SQLInjectionPatternChecker, PDFReportGenerator
from Sql_injection.Static_Analysis.static_analyzer import *
from Sql_injection.Dynamic_Analysis.dynamic_analyzer_new import *
from Sql_injection.Dynamic_Analysis.dynamic_parser import FormParser
from CSRF.CSRF import run_csrf_detection 
from SSRF.SSRF import SSRFVulnerabilityDetector
from XSS.XSS import XSSVulnerabilityScanner
from core.theme_config import get_current_theme, load_theme_config,set_theme,THEMES


# Initialize theme
load_theme_config()


async def run_xss_detection(url, report_format, report_filename, debug_mode=False):
    """Run XSS detection with the specified parameters and handle reporting"""
    try:
        form_parser = FormParser()
        scanner = XSSVulnerabilityScanner(url, form_parser, report_filename)
        
        if debug_mode:
            print(f"{CURRENT_THEME.secondary}[DEBUG] Starting XSS scan for URL: {url}{Style.RESET_ALL}")
            print(f"{CURRENT_THEME.secondary}[DEBUG] Report will be saved as: {report_filename}{Style.RESET_ALL}")
        
        # Run the scan
        result = await scanner.scan(url, report_format)
        
        if result:
            if debug_mode:
                print(f"{CURRENT_THEME.secondary}[DEBUG] Scan completed successfully{Style.RESET_ALL}")
            
            # FIX: Get vulnerabilities from report_generator
            vulnerabilities = scanner.report_generator.form_results + scanner.report_generator.field_results
            
            if vulnerabilities:
                if debug_mode:
                    print(f"{CURRENT_THEME.secondary}[DEBUG] Found {len(vulnerabilities)} vulnerabilities{Style.RESET_ALL}")
                
                print(f"\n{CURRENT_THEME.success}XSS scan completed!{Style.RESET_ALL}")
                print(f"{CURRENT_THEME.text}Found {len(vulnerabilities)} potential XSS vulnerabilities.{Style.RESET_ALL}")
                print(f"{CURRENT_THEME.text}Report saved to: {result}{Style.RESET_ALL}")
            else:
                print(f"\n{CURRENT_THEME.success}XSS scan completed!{Style.RESET_ALL}")
                print(f"{CURRENT_THEME.text}No XSS vulnerabilities were detected.{Style.RESET_ALL}")
                print(f"{CURRENT_THEME.text}Report saved to: {result}{Style.RESET_ALL}")
        else:
            print(f"\n{CURRENT_THEME.alert}XSS scan completed but report generation failed.{Style.RESET_ALL}")
    
    except Exception as e:
        error_msg = str(e)
        print(f"\n{CURRENT_THEME.alert}Error during XSS scan: {error_msg}{Style.RESET_ALL}")
        if debug_mode:
            import traceback
            print(traceback.format_exc())

async def run_xss_scan(scanner, url, report_format, report_filename, debug_mode=False):
    """Run the XSS scan with UI enhancements"""
    try:
        # Capture the start time
        start_time = time.time()
        
        # Perform the scan
        result = await scanner.scan(url, report_format)
        
        # Calculate scan duration
        duration = time.time() - start_time
        
        if result:
            show_fancy_spinner("Generating report", duration=1.5, spinner_type="dots")
            glitch_text("Report generated successfully!", color=CURRENT_THEME.success)
            
            # Get scan results - FIX: Get vulnerabilities from report_generator
            vulnerabilities = scanner.report_generator.form_results + scanner.report_generator.field_results
            
            if vulnerabilities:
                # Prepare vulnerability data for UI display
                xss_data = []
                for vuln in vulnerabilities:
                    severity = scanner.report_generator.get_risk_level(vuln.get('technique', 'Unknown'))[0]
                    xss_data.append([
                        vuln.get('field_or_form', 'N/A'), 
                        severity, 
                        vuln.get('technique', 'Unknown')
                    ])
                
                # Show scan results in a rich table
                show_rich_table(["Target", "Severity", "Type"], xss_data, title="XSS VULNERABILITIES")
                
                # Risk rating calculation
                total_risk_score = 0
                for vuln in vulnerabilities:
                    technique = vuln.get('technique', '')
                    if 'Stored' in technique:
                        total_risk_score += 10
                    elif 'Reflected' in technique:
                        total_risk_score += 7
                    elif 'DOM' in technique:
                        total_risk_score += 5
                
                # Risk rating display
                risk_rating = "Low"
                if total_risk_score > 20:
                    risk_rating = f"{CURRENT_THEME.alert}Critical{Style.RESET_ALL}"
                elif total_risk_score > 10:
                    risk_rating = f"{CURRENT_THEME.alert}High{Style.RESET_ALL}"
                elif total_risk_score > 5:
                    risk_rating = f"{CURRENT_THEME.secondary}Medium{Style.RESET_ALL}"
                
                # Scan Summary
                summary_content = f"""
            Target: {url}
            Vulnerabilities: {len(vulnerabilities)}
            Risk Score: {total_risk_score}
            Overall Risk: {risk_rating}
            Scan Duration: {duration:.2f} seconds

            Report saved to: {report_filename}
            """
                show_rich_panel(summary_content, title="SCAN SUMMARY")
            else:
                glitch_text("No XSS vulnerabilities found.", color=CURRENT_THEME.success)
        else:
            glitch_text("Scan completed but no report was generated.", color=CURRENT_THEME.alert)
    
    except Exception as e:
        glitch_text(f"Error during XSS scan: {e}", color=CURRENT_THEME.alert)
        if debug_mode:
            import traceback
            print(traceback.format_exc())

# Initialize rich console
console = Console()

# Initialize colorama
init(autoreset=True)

CURRENT_THEME = get_current_theme()

# # Define Rich-specific colors for use with Rich components
# RICH_COLORS = {
#     "matrix": {
#         "primary": "green",
#         "secondary": "light_green",
#         "accent": "white",
#         "text": "light_green",
#         "alert": "red",
#         "success": "green",
#         "border": "green"
#     },
#     "neon": {
#         "primary": "magenta",
#         "secondary": "cyan",
#         "accent": "yellow",
#         "text": "cyan",
#         "alert": "red",
#         "success": "green",
#         "border": "magenta"
#     },
#     "midnight": {
#         "primary": "blue",
#         "secondary": "cyan",
#         "accent": "white",
#         "text": "cyan",
#         "alert": "red",
#         "success": "green",
#         "border": "blue"
#     },
#     "blood": {
#         "primary": "red",
#         "secondary": "red",
#         "accent": "white",
#         "text": "red",
#         "alert": "yellow",
#         "success": "green",
#         "border": "red"
#     },
#     "terminal": {
#         "primary": "white",
#         "secondary": "white",
#         "accent": "green",
#         "text": "white",
#         "alert": "red",
#         "success": "green",
#         "border": "white"
#     }
# }


# # Theme colors with rich integration
# class Theme:
#     def __init__(self, name, primary, secondary, accent, text, alert, success, panel_style,description):
#         self.name = name
#         self.primary = primary
#         self.secondary = secondary
#         self.accent = accent
#         self.text = text
#         self.alert = alert
#         self.success = success
#         self.panel_style = panel_style
#         self.description = description 
        
#         # Add Rich colors based on the theme name
#         if name.lower() in RICH_COLORS:
#             self.rich_colors = RICH_COLORS[name.lower()]
#         else:
#             # Default to matrix theme colors if theme not found
#             self.rich_colors = RICH_COLORS["matrix"]

# # Enhanced themes with richer color combinations
# THEMES = {
#     "matrix": Theme(
#         "Matrix", 
#         Fore.GREEN, 
#         Fore.LIGHTGREEN_EX, 
#         Fore.WHITE, 
#         Fore.LIGHTGREEN_EX, 
#         Fore.RED, 
#         Fore.GREEN,
#         {"border_style": "green", "title_align": "center"},
#         Fore.YELLOW  # Description color (Example: Yellow)
#     ),
#     "neon": Theme(
#         "Neon Cyberpunk", 
#         Fore.MAGENTA, 
#         Fore.CYAN, 
#         Fore.YELLOW, 
#         Fore.LIGHTCYAN_EX, 
#         Fore.RED, 
#         Fore.LIGHTGREEN_EX,
#         {"border_style": "magenta", "title_align": "center"},
#         Fore.LIGHTMAGENTA_EX  # Description color (Example: Light Magenta)
#     ),
#     "midnight": Theme(
#         "Midnight Hacker", 
#         Fore.BLUE, 
#         Fore.LIGHTBLUE_EX, 
#         Fore.WHITE, 
#         Fore.LIGHTCYAN_EX, 
#         Fore.RED, 
#         Fore.GREEN,
#         {"border_style": "blue", "title_align": "center"},
#         Fore.LIGHTBLUE_EX  # Description color (Example: Light Blue)
#     ),
#     "blood": Theme(
#         "Blood Dragon", 
#         Fore.RED, 
#         Fore.LIGHTRED_EX, 
#         Fore.WHITE, 
#         Fore.LIGHTRED_EX, 
#         Fore.YELLOW, 
#         Fore.GREEN,
#         {"border_style": "red", "title_align": "center"},
#         Fore.YELLOW  # Description color (Example: Yellow)
#     ),
#     "terminal": Theme(
#         "Classic Terminal", 
#         Fore.WHITE, 
#         Fore.LIGHTWHITE_EX, 
#         Fore.GREEN, 
#         Fore.LIGHTWHITE_EX, 
#         Fore.RED, 
#         Fore.GREEN,
#         {"border_style": "white", "title_align": "center"},
#         Fore.CYAN  # Description color (Example: Cyan)
#     )
# }


# # Default theme
# CURRENT_THEME = THEMES["matrix"]

# Animation speed settings
ANIMATION_SPEED = {
    "typing": 0.005,
    "loading": 0.2,
    "progress": 0.1
}

def get_terminal_size():
    """Get current terminal size with fallback"""
    try:
        columns, rows = shutil.get_terminal_size()
        return columns, rows
    except:
        return 80, 24  # Default fallback size

def center_text(text, width=None):
    """Center text according to terminal width"""
    if width is None:
        width, _ = get_terminal_size()
    return text.center(width)

def clear_screen():
    """Clear screen with cross-platform support"""
    os.system('cls' if os.name == 'nt' else 'clear')

def cursor_hide():
    """Hide cursor"""
    print('\033[?25l', end='')

def cursor_show():
    """Show cursor"""
    print('\033[?25h', end='')

def typed_print(text, speed=None, newline=True, color=None):
    """Print text with typing animation"""
    if speed is None:
        speed = ANIMATION_SPEED["typing"]
    
    if color is None:
        color = CURRENT_THEME.text
    
    cursor_hide()
    for char in text:
        sys.stdout.write(f"{color}{char}")
        sys.stdout.flush()
        time.sleep(speed)
    
    if newline:
        print()
    
    cursor_show()

def glitch_text(text, iterations=3, delay=0.05, color=None):
    """Create a glitch effect for text"""
    if color is None:
        color = CURRENT_THEME.accent
    
    glitch_chars = "!@#$%^&*()_+-={}[]|\\:;\"'<>,.?/~`"
    
    for _ in range(iterations):
        glitched = ""
        for char in text:
            if random.random() > 0.7 and char.strip():  # 30% chance to glitch non-space chars
                glitched += random.choice(glitch_chars)
            else:
                glitched += char
        
        print(f"\r{color}{glitched}{Style.RESET_ALL}", end="")
        sys.stdout.flush()
        time.sleep(delay)
    
    # Print the final clean text
    print(f"\r{color}{text}{Style.RESET_ALL}")

def hacker_progress(task, steps=10, speed=None):
    """Display an animated cyberpunk/hacker style progress bar"""
    if speed is None:
        speed = ANIMATION_SPEED["progress"]
    
    width, _ = get_terminal_size()
    bar_length = min(60, width - 20)  # Ensure bar fits in terminal
    
    # Cool characters for hacker effect
    fill_chars = "█▓▒░"
    empty_char = "░"
    
    print(f"{CURRENT_THEME.secondary}{task}{Style.RESET_ALL}")
    
    cursor_hide()
    for i in range(steps + 1):
        progress = i / steps
        filled_length = int(bar_length * progress)
        empty_length = bar_length - filled_length
        
        # Create a "hacker" style bar with varied characters
        filled_part = ""
        for j in range(filled_length):
            if j > filled_length - 3 and filled_length > 3:
                # Use different chars at leading edge for cool effect
                filled_part += random.choice(fill_chars)
            else:
                filled_part += "█"
        
        # Add "scanning" effect
        if i < steps:
            scan_pos = random.randint(filled_length, filled_length + min(5, empty_length - 1)) if empty_length > 1 else filled_length
            bar = (filled_part + 
                  empty_char * (scan_pos - filled_length) +
                  "▓" +  # Scanning point
                  empty_char * (empty_length - (scan_pos - filled_length) - 1))
        else:
            bar = filled_part + empty_char * empty_length
        
        # Add some random hex values for a technical feel
        hex_val = "".join(random.choice("0123456789ABCDEF") for _ in range(4))
        
        percentage = int(progress * 100)
        print(f"\r{CURRENT_THEME.primary}[{CURRENT_THEME.accent}{bar}{CURRENT_THEME.primary}] {percentage}% {CURRENT_THEME.secondary}[0x{hex_val}]{Style.RESET_ALL}", end="")
        sys.stdout.flush()
        
        # Random delay for more natural feel
        delay = speed * random.uniform(0.8, 1.2)
        time.sleep(delay)
    
    print()  # Final newline
    cursor_show()
    
    # Show completion message with glitch effect
    if steps > 0:
        print(f"{CURRENT_THEME.accent}└─ ", end="")
        glitch_text(f"Process complete", iterations=2, color=CURRENT_THEME.success)

def show_fancy_spinner(message, duration=3, spinner_type="dots"):
    """Show an animated spinner with message"""
    spinners = {
        "dots": ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
        "line": ["|", "/", "-", "\\"],
        "brackets": ["⟨⟩", "⟪⟫", "«»", "‹›"],
        "arrows": ["←", "↖", "↑", "↗", "→", "↘", "↓", "↙"],
        "cyber": ["⌾", "⊗", "⊙", "⨁", "◉", "◎", "○", "◌"],
    }
    
    # Choose spinner characters
    spinner = spinners.get(spinner_type, spinners["dots"])
    
    # Set time between spinner updates
    delay = 0.1
    iterations = int(duration / delay)
    
    cursor_hide()
    
    for i in range(iterations):
        current = spinner[i % len(spinner)]
        
        # Occasionally add random hex for tech effect
        if random.random() > 0.8:
            hex_suffix = f" {CURRENT_THEME.secondary}[0x{random.randint(1000, 9999):X}]{Style.RESET_ALL}"
        else:
            hex_suffix = ""
            
        print(f"\r{CURRENT_THEME.primary}{current} {CURRENT_THEME.text}{message}{hex_suffix}", end="")
        sys.stdout.flush()
        time.sleep(delay)
    
    print()
    cursor_show()

def animated_logo():
    """Display animated ASCII logo with matrix effect"""
    # Get terminal dimensions
    width, height = get_terminal_size()
    
    # Create the logo using pyfiglet
    logo_text = "KALKI"
    
    # Choose a good font that's clearly legible
    fonts = ["big", "speed", "slant", "banner3-D", "dotmatrix"]
    chosen_font = random.choice(fonts)
    
    try:
        logo = pyfiglet.figlet_format(logo_text, font=chosen_font)
    except:
        # Fallback to default font if the chosen one fails
        logo = pyfiglet.figlet_format(logo_text)
    
    # Split logo into lines
    logo_lines = logo.split('\n')
    non_empty_lines = [line for line in logo_lines if line.strip()]
    
    # Matrix rain effect before logo
    chars = "01"
    
    clear_screen()
    cursor_hide()
    
    # Matrix rain effect
    for _ in range(5):  # Number of "rain" iterations
        # Print random 0/1 characters
        print(CURRENT_THEME.primary + ''.join(random.choice(chars) for _ in range(width)))
        time.sleep(0.1)
    
    clear_screen()
    
    # Animate the logo drawing
    for i in range(len(non_empty_lines)):
        # Print the logo lines we've revealed so far
        for j in range(i+1):
            if j < len(non_empty_lines):
                # Center the logo
                centered_line = non_empty_lines[j].center(width)
                print(f"{CURRENT_THEME.primary}{centered_line}")
        
        # Fill the rest of the screen with matrix characters, but fading
        fade_factor = (i+1) / len(non_empty_lines)
        matrix_lines = max(0, height - (i+1) - 3)  # Leave a few lines at the bottom
        for _ in range(matrix_lines):
            if random.random() > fade_factor:  # Less matrix effect as logo appears
                matrix_line = ''.join(random.choice(chars) for _ in range(width))
                print(f"{CURRENT_THEME.primary}{matrix_line}")
        
        time.sleep(0.15)
        clear_screen()
    
    # Final display of the full logo
    for line in non_empty_lines:
        centered_line = line.center(width)
        print(f"{CURRENT_THEME.primary}{centered_line}")
    
    # Add subtitle with typing effect
    subtitle = "VULNERABILITIES ASSESSMENT TOOL"
    centered_subtitle = center_text(subtitle, width)
    print()
    typed_print(centered_subtitle, speed=0.01, color=CURRENT_THEME.secondary)
    print()
    
    version = "v1.0.0"
    print(f"{CURRENT_THEME.text}{version.rjust(width - 5)}")
    
    cursor_show()

def show_console_prompt(text=None):
    """Show a stylish console prompt"""
    if text:
        prompt = f"{CURRENT_THEME.secondary}┌─[{CURRENT_THEME.accent}KALKI{CURRENT_THEME.secondary}]─[{CURRENT_THEME.primary}{text}{CURRENT_THEME.secondary}]\n"
        prompt += f"└──╼ {CURRENT_THEME.accent}❯{Style.RESET_ALL} "
    else:
        prompt = f"{CURRENT_THEME.secondary}┌─[{CURRENT_THEME.accent}KALKI{CURRENT_THEME.secondary}]\n"
        prompt += f"└──╼ {CURRENT_THEME.accent}❯{Style.RESET_ALL} "
    
    return prompt

def get_user_input(prompt_text=None):
    """Get user input with custom prompt"""
    return input(show_console_prompt(prompt_text))

def show_rich_panel(content, title=None, width=None):
    """Display content in a beautiful rich panel"""
    if width is None:
        width, _ = get_terminal_size()
        width = min(width - 5, 100)  # Ensure panel fits in terminal
    
    # Use the rich_colors attribute instead of Colorama colors
    border_style = CURRENT_THEME.rich_colors["border"]
    
    panel = Panel(
        content, 
        title=title,
        width=width,
        title_align="center",
        border_style=border_style
    )
    
    console.print(panel)

# Fix show_rich_table function to use rich_colors
def show_rich_table(headers, data, title=None):
    """Display data in a beautiful rich table"""
    table = Table(title=title, box=box.ROUNDED)
    
    # Use rich_colors instead of Colorama colors
    header_style = CURRENT_THEME.rich_colors["accent"]
    column_style = CURRENT_THEME.rich_colors["secondary"]
    
    # Add headers
    for header in headers:
        table.add_column(header, style=column_style, header_style=header_style)
    
    # Add rows
    for row in data:
        table.add_row(*[str(item) for item in row])
        
    console.print(table)

def show_system_info():
    """Display current system information in a styled box"""
    system = platform.system()
    release = platform.release()
    machine = platform.machine()
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create info tables with rich - use the rich_colors
    table = Table(box=box.ROUNDED, show_header=False)
    
    # Use rich_colors instead of Colorama colors
    text_style = CURRENT_THEME.rich_colors["text"]
    accent_style = CURRENT_THEME.rich_colors["accent"]
    border_style = CURRENT_THEME.rich_colors["border"]
    
    table.add_column("Property", style=text_style)
    table.add_column("Value", style=accent_style)
    
    table.add_row("System", system)
    table.add_row("Release", release)
    table.add_row("Architecture", machine)
    table.add_row("Current Time", current_time)
    
    panel = Panel(
        table,
        title="SYSTEM INFORMATION",
        border_style=border_style,
        title_align="center"
    )
    
    console.print(panel)

def show_banner():
    """Display an enhanced hacker-style banner for the tool"""
    clear_screen()
    animated_logo()
    time.sleep(0.5)
    show_system_info()

def show_menu_header(title):
    """Display an enhanced header for menus"""
    # Convert to uppercase and create Figlet title
    title = title.upper()
    
    try:
        fancy_title = pyfiglet.figlet_format(title, font="slant")
    except:
        fancy_title = pyfiglet.figlet_format(title)  # Fallback
    
    width, _ = get_terminal_size()
    
    # Create border and spacing
    print(f"\n{CURRENT_THEME.secondary}{'═' * width}{Style.RESET_ALL}")
    
    # Print title
    for line in fancy_title.split('\n'):
        if line.strip():
            print(f"{CURRENT_THEME.primary}{line.center(width)}{Style.RESET_ALL}")
    
    # Bottom border
    print(f"{CURRENT_THEME.secondary}{'═' * width}{Style.RESET_ALL}")
    
    # Show breadcrumb navigation
    print(f"{CURRENT_THEME.text}KALKI ❯ {title}{Style.RESET_ALL}")

def animated_menu_option(number, text, description=None, selected=False):
    """Show an animated menu option with optional hover effect"""
    if selected:
        prefix = f"{CURRENT_THEME.accent}[{number}] {CURRENT_THEME.primary}{text}{Style.RESET_ALL}"
    else:
        prefix = f"{CURRENT_THEME.secondary}[{number}] {CURRENT_THEME.text}{text}{Style.RESET_ALL}"
    
    if description:
        print(f"{prefix}\n    {CURRENT_THEME.description}{description}{Style.RESET_ALL}")
    else:
        print(prefix)

def show_startup_sequence():
    """Display an enhanced system startup sequence"""
    systems = [
        ("Core security modules", "Initializing vulnerability scanning engine"),
        ("Threat database", "Loading latest security signatures"),
        ("Network analysis modules", "Configuring packet inspection"),
        ("Exploitation framework", "Preparing assessment toolkit"),
        ("Reporting engine", "Setting up visualization pipeline"),
        ("Defence systems", "Enabling security measures")
    ]
    
    clear_screen()
    print(f"\n{CURRENT_THEME.secondary}[SYSTEM INITIALIZATION]{Style.RESET_ALL}")
    
    # Use standard Rich styles instead of theme colors for Progress
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=50),
        TextColumn("[bold green]{task.percentage:>3.0f}%")
    ) as progress:
        tasks = []
        for system, description in systems:
            tasks.append(progress.add_task(f"{system}", total=100))
        
        total_steps = 100
        for step in range(total_steps):
            for task_id in tasks:
                # Update progress with slightly different speeds
                if progress.tasks[task_id].completed < 100:
                    progress.update(task_id, advance=random.uniform(0.5, 1.5))
            
            time.sleep(0.02)
    
    # Final confirmation
    print(f"\n{CURRENT_THEME.success}┌──[✓] All systems initialized successfully")
    print(f"{CURRENT_THEME.success}└──[✓] Ready for security operations{Style.RESET_ALL}")
    time.sleep(1)

def handle_graceful_exit(signal_received=None, frame=None):
    """Handle program exit with fancy animation"""
    print("\n\n")  # Ensure we start on a clean line
    
    shutdown_messages = [
        "Disconnecting security modules",
        "Clearing sensitive data",
        "Saving configuration",
        "Shutting down services"
    ]
    
    # Show shutdown progress
    cursor_hide()
    for msg in shutdown_messages:
        sys.stdout.write(f"{CURRENT_THEME.secondary}[*] {msg}... ")
        sys.stdout.flush()
        time.sleep(0.3)
        print(f"{CURRENT_THEME.success}Done{Style.RESET_ALL}")
    
    # Final exit message with typing effect
    print("\n")
    typed_print("Thank you for using Kalki Security Assessment Tool", 
                speed=0.01, color=CURRENT_THEME.success)
    typed_print("Stay secure. Hack responsibly.", 
                speed=0.03, color=CURRENT_THEME.secondary)
    cursor_show()
    
    # Matrix effect for dramatic exit
    time.sleep(0.5)
    print("\n")
    chars = "10"
    width, _ = get_terminal_size()
    
    for i in range(5):  # 5 lines of falling effect
        line = ''.join(random.choice(chars) for _ in range(width))
        # Fade effect
        fade_factor = (5-i)/5
        faded_line = ""
        for char in line:
            if random.random() < fade_factor:
                faded_line += char
            else:
                faded_line += " "
        print(f"{CURRENT_THEME.primary}{faded_line}{Style.RESET_ALL}")
        time.sleep(0.1)
    
    # Exit cleanly
    sys.exit(0)

def setup_signal_handlers():
    """Set up handlers for signals to ensure graceful exit"""
    # Register for SIGINT (Ctrl+C) and SIGTERM
    signal.signal(signal.SIGINT, handle_graceful_exit)
    signal.signal(signal.SIGTERM, handle_graceful_exit)

def safe_operation_wrapper(func):
    """Enhanced decorator for error handling"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print(f"\n\n{CURRENT_THEME.secondary}⚠ Operation canceled by user.{Style.RESET_ALL}")
            time.sleep(1)
            
            # Simulate recovery
            show_fancy_spinner("Returning to previous state", duration=2)
            return None
        except Exception as e:
            # Enhanced error display
            error_type = type(e).__name__
            error_msg = str(e)
            
            print(f"\n{CURRENT_THEME.alert}╔══ ERROR DETECTED ══╗{Style.RESET_ALL}")
            print(f"{CURRENT_THEME.alert}║ {error_type}: {error_msg}")
            print(f"{CURRENT_THEME.alert}╚{'═' * (len(error_type) + len(error_msg) + 2)}╝{Style.RESET_ALL}")
            
            # Recovery animation
            time.sleep(1)
            show_fancy_spinner("Recovering from error", duration=2)
            return None
    return wrapper
#main.py
def show_settings_menu():
    """Enhanced settings menu with tabs and previews"""
    global CURRENT_THEME, ANIMATION_SPEED
    
    while True:
        clear_screen()
        show_menu_header("SETTINGS")
        CURRENT_THEME = get_current_theme() 
        
        # Create a simple tabbed interface
        settings_tabs = ["Appearance", "Performance", "Advanced"]
        
        # Show tabs
        print("\n")
        for i, tab in enumerate(settings_tabs):
            if i == 0:  # Always show Appearance tab by default
                print(f"{CURRENT_THEME.accent}┌{'─' * 12}┐  {'┌' + '─' * 12 + '┐  ' * (len(settings_tabs)-1)}")
                print(f"│ {CURRENT_THEME.primary}{tab}{' ' * (10-len(tab))}│  ", end="")
            else:
                print(f"│ {CURRENT_THEME.secondary}{tab}{' ' * (10-len(tab))}│  ", end="")
        print("\n" + f"{CURRENT_THEME.accent}└{'─' * 12}┘  {'└' + '─' * 12 + '┘  ' * (len(settings_tabs)-1)}")
        
        # Show theme settings
        print(f"\n{CURRENT_THEME.secondary}▶ Theme Options:{Style.RESET_ALL}")
        print(f"{CURRENT_THEME.text}  Current Theme: {CURRENT_THEME.name}{Style.RESET_ALL}")
        
        # Display themes with preview of their colors
        for i, (theme_key, theme) in enumerate(THEMES.items(), 1):
            theme_indicator = "✓ " if theme.name == CURRENT_THEME.name else "  "
            print(f"{theme_indicator}{theme.primary}[{i}] {theme.name} {theme.secondary}██{theme.accent}██{theme.text}██{Style.RESET_ALL}")
        
        # Animation speed settings
        print(f"\n{CURRENT_THEME.secondary}▶ Animation Settings:{Style.RESET_ALL}")
        print(f"  [{len(THEMES) + 1}] Animation Speed: {ANIMATION_SPEED['typing']:.3f}s (typing) / {ANIMATION_SPEED['loading']:.1f}s (loading)")
        
        # System settings
        print(f"\n{CURRENT_THEME.secondary}▶ System:{Style.RESET_ALL}")
        print(f"  [{len(THEMES) + 2}] Return to Main Menu")
        
        # Get user input
        choice = get_user_input("Settings")
        
        try:
            choice_num = int(choice)
            if 1 <= choice_num <= len(THEMES):
                # Set theme
                theme_key = list(THEMES.keys())[choice_num - 1]
                set_theme(theme_key) 
               
                CURRENT_THEME = get_current_theme() 
                # Show preview of the new theme
                clear_screen()
                
                print(f"\n{CURRENT_THEME.primary}■ Primary Color")
                print(f"{CURRENT_THEME.secondary}■ Secondary Color")
                print(f"{CURRENT_THEME.accent}■ Accent Color")
                print(f"{CURRENT_THEME.text}■ Text Color")
                print(f"{CURRENT_THEME.alert}■ Alert Color")
                print(f"{CURRENT_THEME.success}■ Success Color{Style.RESET_ALL}")
                
                glitch_text(f"Theme changed to {CURRENT_THEME.name}!", color=CURRENT_THEME.success)
                time.sleep(1)
                
            elif choice_num == len(THEMES) + 1:
                # Animation speed settings
                print(f"\n{CURRENT_THEME.secondary}Animation Speed Settings:{Style.RESET_ALL}")
                print(f"{CURRENT_THEME.text}1. Fast  [typing: 0.001s | loading: 0.1s]{Style.RESET_ALL}")
                print(f"{CURRENT_THEME.text}2. Normal [typing: 0.005s | loading: 0.2s]{Style.RESET_ALL}")
                print(f"{CURRENT_THEME.text}3. Slow  [typing: 0.01s  | loading: 0.3s]{Style.RESET_ALL}")
                
                speed_choice = get_user_input("Speed")
                
                if speed_choice == '1':
                    ANIMATION_SPEED["typing"] = 0.001
                    ANIMATION_SPEED["loading"] = 0.1
                    ANIMATION_SPEED["progress"] = 0.05
                    glitch_text("Animation speed set to Fast", color=CURRENT_THEME.success)
                elif speed_choice == '2':
                    ANIMATION_SPEED["typing"] = 0.005
                    ANIMATION_SPEED["loading"] = 0.2
                    ANIMATION_SPEED["progress"] = 0.1
                    glitch_text("Animation speed set to Normal", color=CURRENT_THEME.success)
                elif speed_choice == '3':
                    ANIMATION_SPEED["typing"] = 0.01
                    ANIMATION_SPEED["loading"] = 0.3
                    ANIMATION_SPEED["progress"] = 0.15
                    glitch_text("Animation speed set to Slow", color=CURRENT_THEME.success)
                else:
                    glitch_text("Invalid choice", color=CURRENT_THEME.alert)
                
                time.sleep(1)
                set_theme(theme_key)
                
            elif choice_num == len(THEMES) + 2:
                # Return to main menu
                break
                
            else:
                glitch_text("Invalid choice", color=CURRENT_THEME.alert)
                time.sleep(1)
                
        except ValueError:
            glitch_text("Invalid choice", color=CURRENT_THEME.alert)
            time.sleep(1)

def display_help():
    """Display enhanced help with sections and rich formatting"""
    clear_screen()
    show_menu_header("HELP")
    
    help_content = """
# Kalki Security Assessment Tool

Kalki is an advanced security assessment platform designed to detect and evaluate various vulnerabilities in web applications and networks.

## Available Scans

1. **SQL Injection Analysis**
   - Static Analysis: Reviews code without execution
   - Dynamic Analysis: Actively tests target websites for vulnerabilities

2. **XSS Vulnerability Analysis**
   - Detects Cross-Site Scripting vulnerabilities
   - Tests for Reflected, Stored, and DOM-based XSS
   - Analyzes JavaScript context escaping issues
   - Validates input sanitization effectiveness

3. **CSRF Vulnerability Analysis**
   - Detects Cross-Site Request Forgery vulnerabilities
   - Examines form implementations and protection mechanisms

4. **SSRF Vulnerability Analysis**
   - Identifies Server-Side Request Forgery vulnerabilities
   - Tests request handling and URL validation

## Best Practices

- Always obtain proper authorization before scanning any system
- Use dedicated testing environments when possible
- Review reports thoroughly and verify findings manually
- Follow responsible disclosure practices

## Command Shortcuts

- `Ctrl+C` - Cancel current operation
- `ESC` - Return to previous menu
- `help` - Show this help menu from anywhere

## XSS Scanning Tips

- Enable JavaScript in your browser configurations
- Test all user-input fields that render content
- Verify both client-side and server-side validation
- Check for proper output encoding and context-aware escaping
"""
    
    show_rich_panel(help_content, title="HELP & DOCUMENTATION")
    
    print(f"\n{CURRENT_THEME.text}Press Enter to return to the main menu...{Style.RESET_ALL}")
    input()

def show_about():
    """Display enhanced about screen with animation"""
    clear_screen()
    show_menu_header("ABOUT")
    
    # Animated version number
    version_text = "V1.0.0"  
    print(f"\n{CURRENT_THEME.secondary}VERSION: ", end="")
    typed_print(version_text, speed=0.05, color=CURRENT_THEME.accent)
    
    # Tool description with rich panel
    about_content = """
Kalki is a comprehensive security assessment platform that combines multiple vulnerability 
scanning techniques in one integrated tool.

The system specializes in detecting:
• SQL Injection vulnerabilities
• Cross-Site Scripting (XSS) attacks
• Cross-Site Request Forgery (CSRF)
• Server-Side Request Forgery (SSRF)

With both static and dynamic analysis capabilities, Kalki provides security 
professionals with powerful tools to identify potential security flaws before 
they can be exploited by malicious actors.
"""
    
    show_rich_panel(about_content, title="ABOUT KALKI")
    
    # Feature list with rich table
    features = [
        ["Static Analysis", "Code review without execution"],
        ["Dynamic Analysis", "Active vulnerability testing"],
        ["XSS Scanner", "Detection of cross-site scripting vulnerabilities"],
        ["Comprehensive Reporting", "Detailed findings with risk assessment"],
        ["Visual Dashboards", "Data visualization for clear insights"],
        ["Multiple Themes", "Customizable interface"]
    ]
    
    show_rich_table(["Feature", "Description"], features, title="Key Features")
    
    # XSS scanning specific information
    xss_info = """
The XSS Scanner module analyzes web applications for cross-site scripting vulnerabilities by:
• Identifying DOM-based XSS vectors
• Testing for reflected and stored XSS vulnerabilities
• Analyzing JavaScript context escaping issues
• Validating input sanitization effectiveness
"""
    show_rich_panel(xss_info, title="XSS Scanner Capabilities")
    
    # Credits section
    print(f"\n{CURRENT_THEME.secondary}DEVELOPED BY:{Style.RESET_ALL}")
    print(f"{CURRENT_THEME.text}TEAM KALKI{Style.RESET_ALL}")
    print(f"\n{CURRENT_THEME.secondary}COPYRIGHT © 2025{Style.RESET_ALL}")
    
    # Animated Disclaimer
    print(f"\n{CURRENT_THEME.alert}DISCLAIMER:{Style.RESET_ALL}")
    disclaimer_text = "This tool should only be used for authorized security assessments. Unauthorized scanning may violate applicable laws."
    typed_print(disclaimer_text, speed=0.01, color=CURRENT_THEME.text)
    
    # Advanced animation - show a little terminal art
    time.sleep(0.5)
    print("\n")
    security_art = """
       /\\
      /  \\
     |    |
     |    |  KALKI
    /|    |\\  SECURITY
   / |    | \\
  /__|____|__\\
 /____________\\
    """
    for line in security_art.split('\n'):
        if line.strip():
            print(f"{CURRENT_THEME.primary}{line}{Style.RESET_ALL}")
            time.sleep(0.05)
    
    # Show a fancy spinner while "loading" something
    show_fancy_spinner("Loading security metrics", duration=1.5, spinner_type="cyber")
    
    # Return prompt
    print(f"\n{CURRENT_THEME.text}Press Enter to return to the main menu...{Style.RESET_ALL}")
    input()

def loading_indicator(message, duration=3):
    print(f"{message}", end="")
    for _ in range(duration):
        time.sleep(0.5)
        print(".", end="")
        sys.stdout.flush()
    print(Style.RESET_ALL)

def progress_bar(task, steps=10, delay=0.2):
    print(f"{task}:", end=" ", flush=True)
    for _ in range(steps):
        print(f"{Fore.CYAN}█{Style.RESET_ALL}", end="", flush=True)
        time.sleep(delay)
    print(" Done!")

# Flashing message
def flashing_message(message, color=Fore.GREEN, flashes=3, delay=0.3):
    for _ in range(flashes):
        print(f"{color}{Style.BRIGHT}{message}{Style.RESET_ALL}")
        time.sleep(delay)
        print("\033[F" + " " * len(message))  # Move back and clear the line
        time.sleep(delay)
    print(f"{color}{Style.BRIGHT}{message}{Style.RESET_ALL}")  # Final message


def fetch_website_code(url):
    session = requests.Session()
    retry = Retry(total=5, backoff_factor=0.3, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)

    try:
        loading_indicator(f"{Fore.GREEN}Fetching code from {url}", duration=6)
        response = session.get(url, timeout=10, verify=False)
        response.raise_for_status()
        print(f"{Fore.GREEN}Website code fetched successfully!{Style.RESET_ALL}")
        return response.text
    except requests.exceptions.RequestException as e:
        flashing_message(f"Failed to fetch website code: {e}", color=Fore.RED)
        raise Exception(f"{Fore.RED}Failed to fetch website code: {e}{Style.RESET_ALL}")

def check_vulnerabilities_from_url(url, report_path):
    try:
        website_code = fetch_website_code(url)

        # Tokenize the code
        print(f"{Fore.YELLOW}Tokenizing the code...{Style.RESET_ALL}")
        progress_bar("Tokenization", steps=15)
        tokenizer = Tokenizer(website_code)
        token_count = tokenizer.tokenize()
        total_tokens = sum(token_count.values())

        # Analyze HTML
        print(f"{Fore.YELLOW}Analyzing HTML code for vulnerabilities...{Style.RESET_ALL}")
        progress_bar("HTML Analysis", steps=20)
        html_checker = HTMLSecurityChecker(website_code)
        html_vulnerabilities = html_checker.analyze_html()

        # Analyze JavaScript
        print(f"\n{Fore.YELLOW}Analyzing JavaScript code for vulnerabilities...{Style.RESET_ALL}")
        progress_bar("JavaScript Analysis", steps=20)
        js_checker = JavaScriptSecurityChecker(website_code)
        js_vulnerabilities = js_checker.analyze_javascript()

        # Check for SQL injection patterns
        print(f"\n{Fore.YELLOW}Checking for SQL injection patterns...{Style.RESET_ALL}")
        progress_bar("SQL Injection Analysis", steps=15)
        sql_checker = SQLInjectionPatternChecker(website_code)
        sql_vulnerabilities = sql_checker.analyze_code()

        # Prepare data for charts
        token_chart_data = {
            'Identifiers': token_count.get('identifier', 0),
            'Strings': token_count.get('string', 0),
            'Numbers': token_count.get('number', 0),
            'Operators': token_count.get('operator', 0),
            'Tags': token_count.get('tag', 0),
            'SQL Keywords': token_count.get('sql_keyword', 0)
        }
        
        vulnerability_counts = {
            'HTML': len(html_vulnerabilities),
            'JavaScript': len(js_vulnerabilities),
            'SQL Injection': len(sql_vulnerabilities)
        }

        # Generate PDF report
        report_generator = PDFReportGenerator()

        # Add Total Token Count
        report_generator.add_section(
            "Total Token Count",
            f"Total Tokens Detected: {total_tokens}"
        )

        # Add Vulnerabilities and Suggestions
        vulnerabilities = html_vulnerabilities + js_vulnerabilities + sql_vulnerabilities
        report_generator.add_vulnerabilities_and_suggestions(vulnerabilities)

        # Add Token Count Table
        report_generator.add_table(
            "Token Count Summary",
            ["Token Type", "Count"],
            [[k, v] for k, v in token_count.items()]
        )

        # Add Token Count Chart
        report_generator.add_chart("Token Type Breakdown", token_chart_data, chart_type='bar')
        
        # Add vulnerability distribution chart
        report_generator.add_chart("Vulnerability Distribution", vulnerability_counts, chart_type='pie')

        # Add summary section
        report_generator.add_summary(vulnerabilities)

        # Ensure the report directory exists
        os.makedirs(report_path, exist_ok=True)
        
        # Save the PDF
        report_file_path = os.path.join(report_path, "static_analysis_sql_injection_report.pdf")
        report_generator.save_report(report_file_path)
        flashing_message(f"PDF report generated successfully at {report_file_path}!", color=Fore.GREEN)
        
        return True, report_file_path

    except Exception as e:
        flashing_message(f"An error occurred: {e}", color=Fore.RED)
        return False, None

async def run_dynamic_analysis(url, report_path):
    """
    Run dynamic analysis with the given URL and report path
    """
    try:
        # Initialize the scanner with the report path
        parser = FormParser()
        scanner = SQLInjectionScanner(url, parser, report_path)
        
        # Run the scan
        print(f"\n{Fore.CYAN}Starting dynamic analysis...{Style.RESET_ALL}")
        scan_success = await scanner.test_sql_injection(url)
        
        if scan_success:
            print(f"\n{Fore.GREEN}Scan completed successfully!{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Generating reports...{Style.RESET_ALL}")
            
            # Generate reports
            report_files = await scanner.generate_final_report()
            
            if report_files:
                print(f"\n{Fore.GREEN}Reports generated successfully in: {report_path}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}Error generating reports.{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}Scan failed or no vulnerabilities found.{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"\n{Fore.RED}Error during dynamic analysis: {str(e)}{Style.RESET_ALL}")

@safe_operation_wrapper
def main():
    """Main application entry point with enhanced UI"""
    setup_signal_handlers()

    try:
        # Show startup sequence and banner
        show_startup_sequence()
        show_banner()
        time.sleep(0.5)
        
        while True:
            # clear_screen()
            # Create a more visually appealing main menu
            show_menu_header("MAIN MENU")
            
            # Display menu options with animations and descriptions
            print("\n")
            animated_menu_option("1", "SQL Injection Analysis", 
                                "Detect SQL injection vulnerabilities through static and dynamic analysis")
            
            animated_menu_option("2", "CSRF Vulnerability Analysis", 
                                "Identify Cross-Site Request Forgery vulnerabilities")
            
            animated_menu_option("3", "SSRF Vulnerability Analysis", 
                                "Detect Server-Side Request Forgery vulnerabilities")
            
            animated_menu_option("4", "XSS Vulnerability Analysis",
                                 "Execution of unauthorized script code in user's browsers through vulnerable websites")
            
            animated_menu_option("5", "Settings", 
                                "Configure theme and animation preferences")
            
            animated_menu_option("6", "Help", 
                                "View documentation and usage guide")
            
            animated_menu_option("7", "About", 
                                "Information about Kalki Security Assessment Tool")
            
            animated_menu_option("8", "Exit", 
                                "Exit the application")
            
            # Get user choice with custom prompt
            choice = get_user_input("Select Option")

            if choice == '1':
                # SQL Injection Analysis
                clear_screen()
                show_menu_header("SQL INJECTION")

                while True:
                    print(f"\n{CURRENT_THEME.secondary}Choose SQL Injection Analysis type:{Style.RESET_ALL}")
                    animated_menu_option("1", "Static Analysis", "Code review without execution")
                    animated_menu_option("2", "Dynamic Analysis", "Active vulnerability testing")
                    animated_menu_option("3", "Back to Main Menu")

                    sql_choice = get_user_input("SQL Injection")

                    if sql_choice == '1':
                        # Static Analysis
                        while True:
                            url = get_user_input("Enter URL for static analysis").strip()
                            if not url:
                                glitch_text("URL cannot be empty. Please try again.", color=CURRENT_THEME.alert)
                                continue
                            
                            # Add http:// if not present
                            if not url.startswith(('http://', 'https://')):
                                url = 'http://' + url
                            break

                        while True:
                            report_path = get_user_input("Enter report save directory (press Enter for current directory)").strip()
                            if not report_path:
                                report_path = "reports"  # Default directory
                            
                            try:
                                os.makedirs(report_path, exist_ok=True)
                                break
                            except Exception as e:
                                glitch_text(f"Error creating directory: {e}", color=CURRENT_THEME.alert)

                        show_rich_panel("Starting static analysis for SQL injection vulnerabilities...", title="STATIC ANALYSIS")
                        hacker_progress("Analyzing target website", steps=15)

                        # Execute real function
                        success, report_file = check_vulnerabilities_from_url(url, report_path)

                        if success:
                            glitch_text("Static analysis completed!", color=CURRENT_THEME.success)
                            show_fancy_spinner("Generating report", duration=2, spinner_type="cyber")

                            report_content = f"""
            Target URL: {url}
            Scan Type: Static Analysis
            Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Report saved to: {report_file}
            """
                            show_rich_panel(report_content, title="SCAN RESULTS")
                        else:
                            glitch_text("Static analysis failed!", color=CURRENT_THEME.alert)

                        print(f"\n{CURRENT_THEME.text}Press Enter to continue...{Style.RESET_ALL}")
                        input()

                    elif sql_choice == '2':
                        # Dynamic Analysis
                        while True:
                            url = get_user_input("Enter URL for dynamic analysis").strip()
                            if not url:
                                glitch_text("URL cannot be empty. Please try again.", color=CURRENT_THEME.alert)
                                continue
                            break

                        while True:
                            report_path = get_user_input("Enter report save path").strip()
                            if not report_path:
                                report_path = "default_dynamic_report.txt"  # Default path if not provided
                            if os.path.exists(os.path.dirname(report_path)):
                                break
                            glitch_text("Invalid path. Please check and try again.", color=CURRENT_THEME.alert)

                        show_rich_panel("Starting dynamic analysis for SQL injection vulnerabilities...", title="DYNAMIC ANALYSIS")

                        scan_steps = [
                            ["Initializing scanner", "Completed"],
                            ["Checking website availability", "Completed"],
                            ["Identifying input vectors", "Completed"],
                            ["Testing parameters", "Completed"],
                            ["Analyzing responses", "Completed"],
                            ["Validating findings", "Completed"]
                        ]
                        for step, status in scan_steps:
                            show_fancy_spinner(step, duration=1, spinner_type="dots")
                            print(f"{CURRENT_THEME.secondary}{step}: {CURRENT_THEME.success}{status}{Style.RESET_ALL}")

                        # Execute real function
                        asyncio.run(run_dynamic_analysis(url, report_path))

                        glitch_text("Dynamic analysis completed!", color=CURRENT_THEME.success)
                        show_fancy_spinner("Generating report", duration=2, spinner_type="cyber")

                        report_content = f"""
            Target URL: {url}
            Scan Type: Dynamic Analysis
            Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            Report saved to: {report_path}
            """
                        show_rich_panel(report_content, title="SCAN RESULTS")

                        print(f"\n{CURRENT_THEME.text}Press Enter to continue...{Style.RESET_ALL}")
                        input()

                    elif sql_choice == '3':
                        break  # Go back to the main menu

                    else:
                        glitch_text("Invalid choice. Please try again.", color=CURRENT_THEME.alert)
                        time.sleep(1)

            #main.py
            elif choice == '2':
                # CSRF Vulnerability Analysis
                clear_screen()
                show_menu_header("CSRF ANALYSIS")
                
                while True:
                    url = get_user_input("Enter URL for CSRF analysis")
                    if url.strip():
                        break
                    glitch_text("URL cannot be empty. Please try again.", color=CURRENT_THEME.alert)

                # Prompt for the report type with enhanced UI
                print(f"\n{CURRENT_THEME.secondary}Select report format:{Style.RESET_ALL}")
                animated_menu_option("1", "CSV Format", "Comma-separated values format")
                animated_menu_option("2", "XLS Format", "Excel spreadsheet format")
                
                report_type_choice = get_user_input("Report Format")
                report_choice = "csv" if report_type_choice == "1" else "xls"
                
                if report_type_choice not in ["1", "2"]:
                    glitch_text("Invalid choice. Defaulting to CSV format.", color=CURRENT_THEME.alert)
                    report_choice = "csv"

                # Prompt user for save path
                while True:
                    save_path = get_user_input("Enter report save directory")
                    if os.path.isdir(save_path):  # Ensure the path is a valid directory
                        break
                    glitch_text("Invalid directory path. Please try again.", color=CURRENT_THEME.alert)
                
                # Advanced options menu
                print(f"\n{CURRENT_THEME.secondary}Configure advanced options?{Style.RESET_ALL}")
                animated_menu_option("Y", "Configure advanced options", "Set timeout, cookies, headers, etc.")
                animated_menu_option("N", "Use default settings", "Standard scan configuration")
                
                advanced_choice = get_user_input("Advanced Options").lower()
                
                # Default configuration values
                timeout = 10
                debug = False
                cookies = None
                user_agent = "CSRF-Scanner/1.0"
                headers = {}
                skip_checks = None
                proxy = None
                scan_depth = 2
                verify_ssl = True
                entropy_threshold = 3.5
                rate_limit_requests = 5
                
                if advanced_choice == 'y':
                    # Show advanced configuration options with fancy UI
                    show_rich_panel("Advanced Configuration Options", title="ADVANCED CONFIG")
                    
                    # Debug mode
                    print(f"\n{CURRENT_THEME.secondary}Debug Mode:{Style.RESET_ALL}")
                    animated_menu_option("Y", "Enable Debug Mode", "Show detailed scan information")
                    animated_menu_option("N", "Disable Debug Mode", "Show only essential information")
                    debug_choice = get_user_input("Debug Mode (Y/N) [Default: N]").lower()
                    if not debug_choice.strip():
                        debug = False
                        glitch_text("No input given. Defaulting to 'Debug Mode: Disabled'.", color=CURRENT_THEME.alert)
                    else:
                        debug = debug_choice == 'y'
                    
                    # Timeout
                    timeout_input = get_user_input("Request timeout in seconds (Default: 10)")
                    if timeout_input.strip():
                        if timeout_input.isdigit():
                            timeout = int(timeout_input)
                        else:
                            glitch_text("Invalid input. Using default timeout (10 seconds).", color=CURRENT_THEME.alert)
                    else:
                        glitch_text("No input provided. Using default timeout (10 seconds).", color=CURRENT_THEME.alert)

                    
                    # Cookie input
                    cookies_input = get_user_input("Custom cookies (format: name1=value1; name2=value2) (Optional)")
                    if cookies_input.strip():
                        cookies = cookies_input
                    else:
                        glitch_text("No input provided. Defaulting to no custom cookies.", color=CURRENT_THEME.alert)

                    # User agent
                    user_agent_input = get_user_input("Custom User-Agent (Default: CSRF-Scanner/1.0)")
                    if user_agent_input.strip():
                        user_agent = user_agent_input
                    else:
                        glitch_text("No input provided. Using default User-Agent: CSRF-Scanner/1.0.", color=CURRENT_THEME.alert)

                    
                    # Proxy
                    proxy_input = get_user_input("Proxy (format: http://user:pass@host:port) (Optional)")
                    if proxy_input.strip():
                        proxy = proxy_input
                    else:
                        glitch_text("No input provided. Defaulting to no proxy.", color=CURRENT_THEME.alert)

                    
                    # Scan depth
                    scan_depth_input = get_user_input("Scan depth for crawling linked pages (Default: 2)")
                    if scan_depth_input.strip():
                        if scan_depth_input.isdigit():
                            scan_depth = int(scan_depth_input)
                        else:
                            glitch_text("Invalid input. Using default scan depth (2).", color=CURRENT_THEME.alert)
                    else:
                        glitch_text("No input provided. Using default scan depth (2).", color=CURRENT_THEME.alert)

                    
                    # Verify SSL
                    print(f"\n{CURRENT_THEME.secondary}Verify SSL certificates:{Style.RESET_ALL}")
                    animated_menu_option("Y", "Verify SSL", "Check certificate validity")
                    animated_menu_option("N", "Skip SSL verification", "Ignore certificate issues")
                    ssl_choice = get_user_input("Verify SSL (Y/N) [Default: Y]").lower()
                    if not ssl_choice.strip():
                        glitch_text("No input given. Defaulting to 'Verify SSL: Yes'.", color=CURRENT_THEME.alert)
                        verify_ssl = True
                    else:
                        verify_ssl = ssl_choice == 'y'
                    
                    # Entropy threshold
                    entropy_input = get_user_input("Entropy threshold for token strength (Default: 3.5)")
                    if entropy_input.strip():
                        try:
                            entropy_threshold = float(entropy_input)
                        except ValueError:
                            glitch_text("Invalid entropy value. Using default (3.5).", color=CURRENT_THEME.alert)
                    else:
                        glitch_text("No input provided. Using default entropy threshold (3.5).", color=CURRENT_THEME.alert)

                    # Rate limit requests
                    rate_limit_input = get_user_input("Number of requests for rate limit testing (Default: 5)")
                    if rate_limit_input.strip():
                        if rate_limit_input.isdigit():
                            rate_limit_requests = int(rate_limit_input)
                        else:
                            glitch_text("Invalid input. Using default rate limit (5 requests).", color=CURRENT_THEME.alert)
                    else:
                        glitch_text("No input provided. Using default rate limit (5 requests).", color=CURRENT_THEME.alert)

                    
                    # Skip checks
                    print(f"\n{CURRENT_THEME.secondary}Skip specific checks (multiple options allowed):{Style.RESET_ALL}")
                    animated_menu_option("1", "Headers", "Skip header-based checks")
                    animated_menu_option("2", "Cookies", "Skip cookie-based checks") 
                    animated_menu_option("3", "Tokens", "Skip CSRF token checks")
                    animated_menu_option("4", "Forms", "Skip form-based checks")
                    animated_menu_option("5", "Rate-limiting", "Skip rate limiting checks")
                    animated_menu_option("0", "None", "Run all checks")
                    
                    skip_input = get_user_input("Skip checks (enter numbers separated by commas) [Default: None]")
                    if not skip_input.strip() or skip_input == "0":
                        glitch_text("No input given. Running all checks by default.", color=CURRENT_THEME.alert)
                        skip_checks = None
                    else:
                        skip_checks = []
                        skip_options = {"1": "headers", "2": "cookies", "3": "tokens", "4": "forms", "5": "rate-limiting"}
                        for option in skip_input.split(","):
                            option = option.strip()
                            if option in skip_options:
                                skip_checks.append(skip_options[option])
                else:
                    # Show the default configuration
                    default_config = f"""
Request Timeout: {timeout} seconds
Debug Mode: {'Enabled' if debug else 'Disabled'}
User-Agent: {user_agent}
Scan Depth: {scan_depth}
Verify SSL: {'Yes' if verify_ssl else 'No'}
Entropy Threshold: {entropy_threshold}
Rate Limit Requests: {rate_limit_requests}
"""
                    show_rich_panel(default_config, title="DEFAULT CONFIGURATION")
                
                # Run CSRF detection with fancy UI
                show_rich_panel("Starting CSRF vulnerability analysis...", title="CSRF SCAN")
                
                # Create a list of scan phases
                csrf_scan_phases = [
                    "Crawling website structure",
                    "Identifying forms and inputs",
                    "Analyzing CSRF tokens",
                    "Testing form submissions",
                    "Validating protective measures",
                    "Assessing vulnerability impact"
                ]
                
                # Show progress for each phase
                for phase in csrf_scan_phases:
                    hacker_progress(phase, steps=random.randint(8, 12))
                
                try:
                    # Run the actual CSRF detection function
                    results = run_csrf_detection(
                        target_url=url,
                        report_choice=report_choice,
                        save_path=save_path,
                        debug=debug,
                        timeout=timeout,
                        cookies=cookies,
                        user_agent=user_agent,
                        headers=headers,
                        skip_checks=skip_checks,
                        proxy=proxy,
                        scan_depth=scan_depth,
                        verify_ssl=verify_ssl,
                        entropy_threshold=entropy_threshold,
                        rate_limit_requests=rate_limit_requests
                    )
                    
                    # Display results
                    glitch_text("CSRF analysis completed!", color=CURRENT_THEME.success)
                    show_fancy_spinner("Generating report", duration=1.5, spinner_type="cyber")
                    
                    # Show scan results in a rich table using actual results
                    # show_rich_table(["Location", "Issue", "Risk"], results["issues"], title="CSRF SCAN RESULTS")
                    
                    # Determine risk color
                    risk_level = results["overall_risk_level"]
                    if risk_level in ["Critical", "High"]:
                        risk_color = CURRENT_THEME.alert
                    elif risk_level == "Medium":
                        risk_color = CURRENT_THEME.secondary
                    else:
                        risk_color = CURRENT_THEME.success
                    
                    # Show summary panel with real results
                    summary_content = f"""
Total forms scanned: {results['forms_scanned']}
Vulnerable forms: {results['vulnerable_forms']}
Total vulnerabilities: {results['total_vulnerabilities']}
Overall risk: {risk_color}{risk_level}{Style.RESET_ALL}
Security score: {results['security_score']}/100
Scan duration: {results['scan_duration']} seconds

Report saved to: {results['report_file']}
"""
                    show_rich_panel(summary_content, title="SCAN SUMMARY")
                    
                except Exception as e:
                    glitch_text(f"Error during CSRF analysis: {e}", color=CURRENT_THEME.alert)
                    if debug:
                        import traceback
                        traceback.print_exc()
                
                print(f"\n{CURRENT_THEME.text}Press Enter to continue...{Style.RESET_ALL}")
                input()

            elif choice == '3':
                # SSRF Vulnerability Analysis
                clear_screen()
                show_menu_header("SSRF SCAN")

                # Validate URL input (User must enter a valid URL)
                url_pattern = re.compile(r'^(http|https):\/\/[^\s]+$')
                while True:
                    url = get_user_input("Enter URL for SSRF analysis").strip()
                    if url_pattern.match(url):
                        break
                    glitch_text("Invalid URL. Please enter a valid HTTP/HTTPS URL.", color=CURRENT_THEME.alert)

                # Prompt for the report type with enhanced UI
                print(f"\n{CURRENT_THEME.secondary}Select report format:{Style.RESET_ALL}")
                animated_menu_option("1", "CSV Format", "Comma-separated values format")
                animated_menu_option("2", "XLS Format", "Excel spreadsheet format")

                report_type_choice = get_user_input("Report Format").strip()
                if report_type_choice not in ["1", "2"]:
                    glitch_text("No input given. Defaulting to CSV format.", color=CURRENT_THEME.alert)
                    report_choice = "csv"
                else:
                    report_choice = "csv" if report_type_choice == "1" else "xls"

                # Prompt user for save path (directory validation)
                save_path = get_user_input("Enter report save directory").strip()
                if not save_path or not os.path.isdir(save_path):  
                    glitch_text("No valid directory provided. Defaulting to current directory (.).", color=CURRENT_THEME.alert)
                    save_path = "."  

                # Prompt for debug mode with a toggle
                print(f"\n{CURRENT_THEME.secondary}Debug Mode:{Style.RESET_ALL}")
                animated_menu_option("Y", "Enable Debug Mode", "Show detailed scan information")
                animated_menu_option("N", "Disable Debug Mode", "Show only essential information")

                debug_choice = get_user_input("Debug Mode").strip().lower()
                if debug_choice not in ["y", "n"]:
                    glitch_text("No input given. Defaulting to Debug Mode: Disabled.", color=CURRENT_THEME.alert)
                    debug_mode = False
                else:
                    debug_mode = debug_choice == 'y'

                try:
                    # Run scan with enhanced UI
                    show_rich_panel("Starting SSRF vulnerability scan...", title="SSRF SCAN")

                    # List of scan stages
                    ssrf_scan_stages = [
                        "Initializing scanner",
                        "Analyzing URL structure",
                        "Identifying potential injection points",
                        "Testing local resources access",
                        "Testing internal network requests",
                        "Testing cloud metadata access",
                        "Validating findings"
                    ]

                    # Initialize scanner
                    scanner = SSRFVulnerabilityDetector(url, debug_mode)

                    # Show progress for each stage
                    for i, stage in enumerate(ssrf_scan_stages):
                        show_fancy_spinner(stage, duration=random.uniform(1.0, 1.5), spinner_type="cyber")
                        print(f"{CURRENT_THEME.secondary}{stage}: {CURRENT_THEME.success}Completed{Style.RESET_ALL}")

                        # Run actual scan after initialization and analysis
                        if i == 3:
                            scanner.detect_ssrf_vulnerabilities()

                    # Get scan results
                    vulnerabilities = scanner.vulnerabilities
                    total_risk_score = scanner.total_risk_score

                    if vulnerabilities:
                        show_fancy_spinner("Generating report", duration=1.5, spinner_type="dots")
                        report_path = scanner.save_report(report_choice, save_path)
                        glitch_text("Report generated successfully!", color=CURRENT_THEME.success)

                        # Prepare vulnerability data for UI display
                        ssrf_data = [[vuln.get('url', 'N/A'), vuln.get('severity', 'Unknown'), vuln.get('type', 'Unknown')]
                                    for vuln in vulnerabilities]

                        # Show scan results in a rich table
                        show_rich_table(["Endpoint", "Severity", "Type"], ssrf_data, title="SSRF VULNERABILITIES")

                        # Risk rating
                        risk_rating = "Low"
                        if total_risk_score > 20:
                            risk_rating = f"{CURRENT_THEME.alert}Critical{Style.RESET_ALL}"
                        elif total_risk_score > 10:
                            risk_rating = f"{CURRENT_THEME.alert}High{Style.RESET_ALL}"
                        elif total_risk_score > 5:
                            risk_rating = f"{CURRENT_THEME.secondary}Medium{Style.RESET_ALL}"

                        # Scan Summary
                        summary_content = f"""
                    Target: {url}
                    Vulnerabilities: {len(vulnerabilities)}
                    Risk Score: {total_risk_score}
                    Overall Risk: {risk_rating}

                    Report saved to: {report_path}
                    """
                        show_rich_panel(summary_content, title="SCAN SUMMARY")
                    else:
                        glitch_text("No SSRF vulnerabilities found.", color=CURRENT_THEME.success)

                except ValueError as e:
                    glitch_text(f"Error: {e}", color=CURRENT_THEME.alert)
                except Exception as e:
                    glitch_text(f"Unexpected error: {e}", color=CURRENT_THEME.alert)

                print(f"\n{CURRENT_THEME.text}Press Enter to continue...{Style.RESET_ALL}")
                input()

            #main.py
            elif choice == '4':
                # XSS Vulnerability Analysis
                clear_screen()
                show_menu_header("XSS SCAN")

                # Validate URL input (User must enter a valid URL)
                url_pattern = re.compile(r'^(http|https):\/\/[^\s]+$')
                while True:
                    url = get_user_input("Enter URL for XSS analysis").strip()
                    if url_pattern.match(url):
                        break
                    glitch_text("Invalid URL. Please enter a valid HTTP/HTTPS URL.", color=CURRENT_THEME.alert)

                # Prompt for the report type with enhanced UI
                print(f"\n{CURRENT_THEME.secondary}Select report format:{Style.RESET_ALL}")
                animated_menu_option("1", "CSV Format", "Comma-separated values format")
                animated_menu_option("2", "XLS Format", "Excel spreadsheet format")
                animated_menu_option("3", "PDF Format", "PDF document format")

                report_type_choice = get_user_input("Report Format").strip()
                if report_type_choice not in ["1", "2", "3"]:
                    glitch_text("No input given. Defaulting to CSV format.", color=CURRENT_THEME.alert)
                    report_choice = "csv"
                else:
                    report_choice = "csv" if report_type_choice == "1" else "xls" if report_type_choice == "2" else "pdf"

                # Prompt user for save path (directory validation)
                save_path = get_user_input("Enter report save directory").strip()
                if not save_path or not os.path.isdir(save_path):  
                    glitch_text("No valid directory provided. Defaulting to current directory (.).", color=CURRENT_THEME.alert)
                    save_path = "."  

                # Prompt for debug mode with a toggle
                print(f"\n{CURRENT_THEME.secondary}Debug Mode:{Style.RESET_ALL}")
                animated_menu_option("Y", "Enable Debug Mode", "Show detailed scan information")
                animated_menu_option("N", "Disable Debug Mode", "Show only essential information")

                debug_choice = get_user_input("Debug Mode").strip().lower()
                if debug_choice not in ["y", "n"]:
                    glitch_text("No input given. Defaulting to Debug Mode: Disabled.", color=CURRENT_THEME.alert)
                    debug_mode = False
                else:
                    debug_mode = debug_choice == 'y'

                try:
                    # Run scan with enhanced UI
                    show_rich_panel("Starting XSS vulnerability scan...", title="XSS SCAN")

                    # List of scan stages
                    xss_scan_stages = [
                        "Initializing scanner",
                        "Analyzing URL structure",
                        "Identifying form elements",
                        "Testing URL parameters",
                        "Testing form inputs",
                        "Testing DOM-based vulnerabilities",
                        "Testing stored XSS vectors",
                        "Validating findings"
                    ]

                    # Generate the report filename with timestamp
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    valid_formats = {"pdf": ".pdf", "csv": ".csv", "xls": ".xlsx"}
                    report_filename = os.path.join(save_path, f"XSS_Report_{timestamp}{valid_formats[report_choice]}")

                    # Initialize parser and scanner
                    form_parser = FormParser()
                    scanner = XSSVulnerabilityScanner(url, form_parser, report_filename)

                    # Show progress for each stage
                    for i, stage in enumerate(xss_scan_stages):
                        show_fancy_spinner(stage, duration=random.uniform(1.0, 1.5), spinner_type="cyber")
                        print(f"{CURRENT_THEME.secondary}{stage}: {CURRENT_THEME.success}Completed{Style.RESET_ALL}")

                    # ✅ Fix: Proper async event loop handling
                    try:
                        loop = asyncio.get_event_loop()
                        if loop.is_running():
                            asyncio.create_task(run_xss_scan(scanner, url, report_choice, report_filename, debug_mode))
                        else:
                            loop.run_until_complete(run_xss_scan(scanner, url, report_choice, report_filename, debug_mode))
                    except RuntimeError:  # Handle case where no event loop exists
                        loop = asyncio.new_event_loop()
                        asyncio.set_event_loop(loop)
                        loop.run_until_complete(run_xss_scan(scanner, url, report_choice, report_filename, debug_mode))

                except ValueError as e:
                    glitch_text(f"Error: {e}", color=CURRENT_THEME.alert)
                except Exception as e:
                    glitch_text(f"Unexpected error: {e}", color=CURRENT_THEME.alert)

                print(f"\n{CURRENT_THEME.text}Press Enter to continue...{Style.RESET_ALL}")
                input()


            elif choice == '5':
                # Settings menu
                show_settings_menu()
                
            elif choice == '6':
                # Help menu
                display_help()
                
            elif choice == '7':
                # About menu
                show_about()
                
            elif choice == '8':
                handle_graceful_exit()

            else:
                glitch_text("Invalid choice. Please try again.", color=CURRENT_THEME.alert)
                time.sleep(1)
                
    except Exception as e:
        print(f"\n{CURRENT_THEME.alert}Unexpected error: {str(e)}{Style.RESET_ALL}")
        handle_graceful_exit()


if __name__ == "__main__":
    main()