#!/usr/bin/env python3
"""
Batch Analysis Entry Point

Main script for running automated batch analysis across all 8 security modules.
Processes documents and URLs, executes modules, and generates HTML dashboard.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))

from common import load_config, ConfigurationError
from batch_analysis import (
    BatchOrchestrator,
    DashboardGenerator
)


def setup_logging(debug: bool = False):
    """Configure logging with enhanced formatting."""
    from colorama import init, Fore, Style
    init(autoreset=True)
    
    level = logging.DEBUG if debug else logging.INFO
    
    # Custom formatter with colors
    class ColoredFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': Fore.CYAN,
            'INFO': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.RED + Style.BRIGHT
        }
        
        def format(self, record):
            # Simplify logger names
            if record.name.startswith('batch_analysis.'):
                record.name = record.name.replace('batch_analysis.', '')
            elif record.name == '__main__':
                record.name = 'batch'
            
            # Add color to level name
            levelname = record.levelname
            if levelname in self.COLORS:
                record.levelname = f"{self.COLORS[levelname]}{levelname}{Style.RESET_ALL}"
            
            return super().format(record)
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter(
        '%(levelname)s %(name)s: %(message)s'
    ))
    
    # File handler without colors
    file_handler = logging.FileHandler('batch_outputs/logs/batch_analysis.log')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    
    # Configure root logger
    logging.basicConfig(
        level=level,
        handlers=[console_handler, file_handler]
    )


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Run automated batch security analysis across all modules.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run batch analysis with default settings
  python run_batch_analysis.py

  # Run with custom input directories
  python run_batch_analysis.py --docs batch_inputs/documents/ --urls batch_inputs/urls/

  # Run specific modules only
  python run_batch_analysis.py --modules 1,2,3,4

  # Generate dashboard only from existing results
  python run_batch_analysis.py --dashboard-only --results batch_outputs/raw_results/

  # Run with debug output
  python run_batch_analysis.py --debug
        """
    )
    
    parser.add_argument(
        "--docs",
        type=str,
        default="batch_inputs/documents",
        help="Path to documents directory (default: batch_inputs/documents/)"
    )
    
    parser.add_argument(
        "--urls",
        type=str,
        default="batch_inputs/urls",
        help="Path to URLs directory (default: batch_inputs/urls/)"
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default="batch_outputs",
        help="Output directory (default: batch_outputs/)"
    )
    
    parser.add_argument(
        "--modules",
        type=str,
        help="Comma-separated module numbers to run (default: all, e.g., 1,2,3,4)"
    )
    
    parser.add_argument(
        "--dashboard-only",
        action="store_true",
        help="Only generate dashboard from existing results"
    )
    
    parser.add_argument(
        "--results",
        type=str,
        help="Path to existing results for dashboard-only mode"
    )
    
    parser.add_argument(
        "--config-dir",
        type=str,
        default="config",
        help="Configuration directory (default: config/)"
    )
    
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging"
    )
    
    parser.add_argument(
        "--no-dashboard",
        action="store_true",
        help="Skip dashboard generation"
    )
    
    return parser.parse_args()


def parse_module_list(modules_str: Optional[str]) -> Optional[List[int]]:
    """Parse comma-separated module numbers."""
    if not modules_str:
        return None
    
    try:
        modules = [int(m.strip()) for m in modules_str.split(",")]
        # Validate module numbers
        for m in modules:
            if m < 1 or m > 8:
                raise ValueError(f"Invalid module number: {m}. Must be 1-8.")
        return modules
    except ValueError as e:
        raise ValueError(f"Invalid module list: {e}")


def print_banner(text: str, color: str = ""):
    """Print a colorful banner."""
    from colorama import Fore, Style
    colors = {
        "blue": Fore.BLUE,
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW,
        "cyan": Fore.CYAN,
        "magenta": Fore.MAGENTA
    }
    c = colors.get(color, "")
    width = 70
    print(f"\n{c}{'═' * width}{Style.RESET_ALL}")
    print(f"{c}{text.center(width)}{Style.RESET_ALL}")
    print(f"{c}{'═' * width}{Style.RESET_ALL}\n")


def print_progress(current: int, total: int, item: str):
    """Print progress indicator."""
    from colorama import Fore, Style
    percentage = int((current / total) * 100) if total > 0 else 0
    bar_length = 30
    filled = int((percentage / 100) * bar_length)
    bar = '█' * filled + '░' * (bar_length - filled)
    print(f"{Fore.CYAN}[{bar}] {percentage}%{Style.RESET_ALL} {item}")


def run_batch_analysis(args: argparse.Namespace) -> int:
    """
    Run batch analysis.
    
    Args:
        args: Command-line arguments
        
    Returns:
        Exit code (0 for success)
    """
    from colorama import Fore, Style
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        print_banner("LOADING CONFIGURATION", "cyan")
        config = load_config(args.config_dir)
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Configuration loaded successfully")
        
        # Parse module list
        modules = parse_module_list(args.modules)
        
        # Create orchestrator
        orchestrator = BatchOrchestrator(
            config=config,
            docs_dir=Path(args.docs),
            urls_dir=Path(args.urls),
            output_dir=Path(args.output),
            debug=args.debug
        )
        
        # Load inputs
        print_banner("LOADING INPUTS", "blue")
        
        inputs = orchestrator.load_inputs()
        
        # Display input summary
        print(f"\n{Fore.CYAN}[DOCUMENTS]{Style.RESET_ALL}")
        print(f"   Parsed: {len(inputs.document_metadata)} files")
        print(f"   Policy References: {len(inputs.policies)}")
        
        print(f"\n{Fore.CYAN}[URLs]{Style.RESET_ALL}")
        print(f"   Total: {len(inputs.urls)}")
        print(f"   Web Apps: {len(inputs.web_urls)}")
        print(f"   APIs: {len(inputs.api_urls)}")
        print(f"   Infrastructure: {len(inputs.infrastructure_urls)}")
        
        if not inputs.urls:
            print(f"\n{Fore.YELLOW}[WARNING]{Style.RESET_ALL} No URLs found in inputs")
            print(f"  Add documents to: {Fore.CYAN}{args.docs}{Style.RESET_ALL}")
            print(f"  Add URL files to: {Fore.CYAN}{args.urls}{Style.RESET_ALL}")
            
            default_target = config.get_target_url()
            print(f"\n{Fore.GREEN}[INFO]{Style.RESET_ALL} Using default target: {default_target}")
            targets = [default_target]
        else:
            targets = inputs.urls
            print(f"\n{Fore.GREEN}[READY]{Style.RESET_ALL} Prepared to scan {len(targets)} targets")
        
        # Execute modules
        print_banner("EXECUTING MODULES", "magenta")
        
        # Show what will be executed
        module_count = len(modules) if modules else 8
        print(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} Executing {module_count} modules on {len(targets)} target(s)\n")
        
        # Add loading indicator
        print(f"{Fore.YELLOW}[PROGRESS]{Style.RESET_ALL} Analysis in progress...")
        
        results = orchestrator.execute_all_modules(
            targets=targets,
            modules=modules
        )
        
        # Show completion
        print(f"\n{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} All modules completed successfully")
        
        # Save results
        print_banner("SAVING RESULTS", "green")
        
        results_file = orchestrator.save_batch_results(results)
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Results saved to: {Fore.CYAN}{results_file}{Style.RESET_ALL}")
        
        # Generate dashboard
        if not args.no_dashboard:
            print_banner("GENERATING DASHBOARD", "yellow")
            
            print(f"{Fore.YELLOW}[PROGRESS]{Style.RESET_ALL} Building HTML dashboard...")
            
            generator = DashboardGenerator(debug=args.debug)
            
            # Convert results to dict
            results_dict = {
                "timestamp": results.timestamp,
                "execution_time": results.execution_time,
                "summary": results.summary,
                "module_results": results.module_results,
                "errors": results.errors
            }
            
            dashboard_path = generator.generate_dashboard(results_dict)
            print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} Dashboard generated: {Fore.CYAN}{dashboard_path}{Style.RESET_ALL}")
            
            # Final summary
            print_banner("ANALYSIS COMPLETE", "green")
            
            # Display summary statistics
            summary = results.summary
            exec_time = results.execution_time
            
            print(f"\n{Fore.CYAN}[SUMMARY] Statistics:{Style.RESET_ALL}\n")
            print(f"   {Fore.GREEN}[OK]{Style.RESET_ALL} Modules Executed: {summary.get('total_modules', 0)}")
            print(f"   {Fore.GREEN}[OK]{Style.RESET_ALL} Successful: {summary.get('successful_modules', 0)}")
            print(f"   {Fore.RED}[FAIL]{Style.RESET_ALL} Failed: {summary.get('failed_modules', 0)}")
            print(f"   {Fore.YELLOW}[TIME]{Style.RESET_ALL} Execution Time: {exec_time/60:.1f} minutes")
            
            print(f"\n{Fore.CYAN}[SUMMARY] Security Controls:{Style.RESET_ALL}\n")
            print(f"   {Fore.GREEN}[PASS]{Style.RESET_ALL} Passed: {summary.get('controls_passed', 0)}")
            print(f"   {Fore.RED}[FAIL]{Style.RESET_ALL} Failed: {summary.get('controls_failed', 0)}")
            print(f"   {Fore.YELLOW}[SKIP]{Style.RESET_ALL} Not Tested: {summary.get('controls_not_tested', 0)}")
            
            print(f"\n{Fore.CYAN}[OUTPUT] Files Generated:{Style.RESET_ALL}\n")
            print(f"   Dashboard: {Fore.CYAN}{dashboard_path}{Style.RESET_ALL}")
            print(f"   Results:   {Fore.CYAN}{results_file}{Style.RESET_ALL}")
            print(f"   Logs:      {Fore.CYAN}batch_outputs/logs/batch_analysis.log{Style.RESET_ALL}")
            
            print(f"\n{Fore.GREEN}{'─' * 70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[COMPLETE] Open the dashboard in your browser to view detailed findings{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'─' * 70}{Style.RESET_ALL}\n")
        
        return 0
        
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        return 2
    except ValueError as e:
        logger.error(f"Invalid argument: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 3


def run_dashboard_only(args: argparse.Namespace) -> int:
    """
    Generate dashboard from existing results.
    
    Args:
        args: Command-line arguments
        
    Returns:
        Exit code (0 for success)
    """
    logger = logging.getLogger(__name__)
    
    try:
        if not args.results:
            logger.error("--results path required for --dashboard-only mode")
            return 1
        
        results_path = Path(args.results)
        if not results_path.exists():
            logger.error(f"Results path not found: {results_path}")
            return 1
        
        # Load results
        import json
        
        if results_path.is_file():
            with open(results_path, 'r') as f:
                results = json.load(f)
        else:
            logger.error("Results path must be a JSON file")
            return 1
        
        # Generate dashboard
        generator = DashboardGenerator(debug=args.debug)
        dashboard_path = generator.generate_dashboard(results)
        
        logger.info(f"Dashboard generated: {dashboard_path}")
        print(f"\n✅ Dashboard generated: {dashboard_path}")
        
        return 0
        
    except Exception as e:
        logger.error(f"Error generating dashboard: {e}", exc_info=True)
        return 3


def main() -> int:
    """Main entry point."""
    args = parse_args()
    
    # Setup logging
    setup_logging(args.debug)
    
    logger = logging.getLogger(__name__)
    logger.info("="*70)
    logger.info("SECURITY CONTROLS GAP ANALYSIS - BATCH MODE")
    logger.info("="*70)
    
    # Run appropriate mode
    if args.dashboard_only:
        return run_dashboard_only(args)
    else:
        return run_batch_analysis(args)


if __name__ == "__main__":
    sys.exit(main())
