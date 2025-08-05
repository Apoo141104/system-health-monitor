#!/usr/bin/env python3
import platform
import subprocess
import time
import requests
import uuid
import json
import logging
import psutil
from datetime import datetime
from typing import Dict, Optional, Tuple, Any
import configparser
import signal
import sys
import os
from pathlib import Path
# Add to your imports
from AppKit import NSStatusBar, NSImage
from AppKit import NSVariableStatusItemLength
import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)  

class SystemTrayIcon:
    def __init__(self):
        self.statusbar = NSStatusBar.systemStatusBar()
        self.statusitem = self.statusbar.statusItemWithLength_(
            NSVariableStatusItemLength)
        self.statusitem.setHighlightMode_(True)
        icon = NSImage.alloc().initWithContentsOfFile_("icon.png")
        self.statusitem.setImage_(icon)
# Constants
DEFAULT_CONFIG = {
    'general': {
        'interval_minutes': '30',
        'max_cpu_usage': '2',  # %
        'max_memory_usage': '50'  # MB
    },
    'api': {
        'endpoint': 'https://your-api-endpoint.com/submit',
        'timeout_seconds': '10',
        'retry_attempts': '3'
    },
    'logging': {
        'level': 'INFO',
        'max_size_mb': '10',
        'backup_count': '3'
    }
}

class SystemHealthMonitor:
    """Main system monitoring class with comprehensive error handling"""
    
    def __init__(self):
        self._setup_directories()
        self._load_config()
        self._setup_logging()
        self._validate_environment()
        self.machine_id = self._get_machine_id()
        self.last_report: Dict[str, Any] = {}
        self._setup_signal_handlers()
        self.shutdown_flag = False
        self.resource_watchdog = ResourceWatchdog(
            max_cpu=float(self.config['general']['max_cpu_usage']),
            max_memory=float(self.config['general']['max_memory_usage'])
        )

    def _setup_directories(self) -> None:
        """Ensure all required directories exist"""
        try:
            self.app_data_dir = Path.home() / '.systemhealthmonitor'
            self.log_dir = self.app_data_dir / 'logs'
            self.config_dir = self.app_data_dir / 'config'
            
            for directory in [self.app_data_dir, self.log_dir, self.config_dir]:
                directory.mkdir(exist_ok=True, parents=True)
        except Exception as e:
            print(f"CRITICAL: Failed to create directories: {e}")
            sys.exit(1)

    def _load_config(self) -> None:
        """Load or create configuration"""
        self.config_path = self.config_dir / 'config.ini'
        self.config = configparser.ConfigParser()
        
        if not self.config_path.exists():
            self._create_default_config()
        
        try:
            self.config.read(self.config_path)
            # Validate required sections
            for section in DEFAULT_CONFIG.keys():
                if section not in self.config:
                    raise ValueError(f"Missing config section: {section}")
        except Exception as e:
            print(f"CRITICAL: Config error: {e}")
            sys.exit(1)

    def _create_default_config(self) -> None:
        """Create default configuration file"""
        try:
            self.config.read_dict(DEFAULT_CONFIG)
            with open(self.config_path, 'w') as f:
                self.config.write(f)
        except Exception as e:
            print(f"CRITICAL: Failed to create config: {e}")
            sys.exit(1)

    def _setup_logging(self) -> None:
        """Configure logging system"""
        try:
            log_level = self.config['logging']['level'].upper()
            log_file = self.log_dir / 'system_health.log'
            
            logging.basicConfig(
                level=log_level,
                format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_file),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger('SystemHealthMonitor')
            self.logger.info("Logging system initialized")
        except Exception as e:
            print(f"CRITICAL: Failed to setup logging: {e}")
            sys.exit(1)

    def _validate_environment(self) -> None:
        """Validate system environment and dependencies"""
        try:
            # Check Python version
            if sys.version_info < (3, 6):
                raise RuntimeError("Python 3.6 or higher required")
            
            # Check required binaries based on OS
            system = platform.system().lower()
            if system == 'linux':
                self._check_linux_dependencies()
            elif system == 'windows':
                self._check_windows_dependencies()
            elif system == 'darwin':
                self._check_macos_dependencies()
            
            self.logger.info("Environment validation passed")
        except Exception as e:
            self.logger.critical(f"Environment validation failed: {e}")
            sys.exit(1)

    def _check_linux_dependencies(self) -> None:
        """Check for required Linux binaries"""
        required = ['lsblk', 'cryptsetup', 'gsettings', 'systemctl']
        missing = []
        for cmd in required:
            try:
                subprocess.run([cmd, '--version'], 
                             stdout=subprocess.DEVNULL, 
                             stderr=subprocess.DEVNULL)
            except FileNotFoundError:
                missing.append(cmd)
        if missing:
            raise RuntimeError(f"Missing required binaries: {', '.join(missing)}")

    def _check_windows_dependencies(self) -> None:
        """Check for required Windows utilities"""
        try:
            subprocess.run(['powershell', '-Command', 'Get-Command'], 
                         stdout=subprocess.DEVNULL, 
                         stderr=subprocess.DEVNULL, 
                         shell=True)
        except FileNotFoundError:
            raise RuntimeError("PowerShell not available")

    def _check_macos_dependencies(self) -> None:
        """Check for required macOS utilities"""
        required = ['fdesetup', 'softwareupdate', 'pmset']
        missing = []
        for cmd in required:
            try:
                subprocess.run([cmd], 
                              stdout=subprocess.DEVNULL, 
                              stderr=subprocess.DEVNULL)
            except FileNotFoundError:
                missing.append(cmd)
        if missing:
            raise RuntimeError(f"Missing required binaries: {', '.join(missing)}")

    def _get_machine_id(self) -> str:
        """Get or generate a stable machine identifier with fallbacks"""
        try:
            system = platform.system().lower()
            if system == 'linux':
                # Try machine-id first
                try:
                    with open('/etc/machine-id') as f:
                        return f.read().strip()
                except:
                    # Fallback to product UUID
                    try:
                        result = subprocess.run(['dmidecode', '-s', 'system-uuid'], 
                                             capture_output=True, text=True)
                        if result.returncode == 0:
                            return result.stdout.strip()
                    except:
                        pass
            
            elif system == 'windows':
                # Try WMIC
                try:
                    result = subprocess.run(
                        ['wmic', 'csproduct', 'get', 'uuid'],
                        capture_output=True, text=True, shell=True
                    )
                    if result.returncode == 0:
                        return result.stdout.split('\n')[2].strip()
                except:
                    pass
            
            elif system == 'darwin':
                # Try IOPlatformUUID
                try:
                    result = subprocess.run(
                        ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice', '|', 'grep', 'IOPlatformUUID'],
                        capture_output=True, text=True, shell=True
                    )
                    if result.returncode == 0:
                        return result.stdout.split('=')[-1].strip().strip('"')
                except:
                    pass
            
            # Final fallback - generate and store a UUID
            fallback_id = str(uuid.uuid4())
            id_file = self.app_data_dir / 'machine_id'
            try:
                if id_file.exists():
                    with open(id_file) as f:
                        return f.read().strip()
                else:
                    with open(id_file, 'w') as f:
                        f.write(fallback_id)
                    return fallback_id
            except:
                return fallback_id
            
        except Exception as e:
            self.logger.error(f"Failed to get machine ID: {e}")
            return str(uuid.uuid4())

    def _setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown"""
        signal.signal(signal.SIGINT, self._handle_shutdown)
        signal.signal(signal.SIGTERM, self._handle_shutdown)
        if platform.system().lower() == 'linux':
            signal.signal(signal.SIGHUP, self._handle_shutdown)

    def _handle_shutdown(self, signum, frame) -> None:
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received shutdown signal {signum}")
        self.shutdown_flag = True

    def check_disk_encryption(self) -> Dict[str, str]:
        """Comprehensive disk encryption check with multiple fallbacks"""
        result = {
            'status': 'unknown',
            'method': 'unknown',
            'details': {}
        }
        
        try:
            system = platform.system().lower()
            
            if system == 'linux':
                result.update(self._check_linux_encryption())
            elif system == 'windows':
                result.update(self._check_windows_encryption())
            elif system == 'darwin':
                result.update(self._check_macos_encryption())
            
            # Additional checks for mounted volumes
            result['mounted_volumes'] = self._check_mounted_volumes()
            
        except Exception as e:
            self.logger.error(f"Disk encryption check failed: {e}")
            result['error'] = str(e)
        
        return result

    def _check_linux_encryption(self) -> Dict[str, str]:
        """Linux-specific encryption checks"""
        result = {}
        
        # Check for LUKS encryption
        try:
            lsblk = subprocess.run(
                ['lsblk', '-o', 'NAME,FSTYPE,MOUNTPOINT,RO', '-J'],
                capture_output=True, text=True
            )
            lsblk_data = json.loads(lsblk.stdout)
            
            root_device = None
            for device in lsblk_data['blockdevices']:
                for mount in device.get('mountpoints', []):
                    if mount == '/':
                        root_device = device['name']
                        break
                if root_device:
                    break
            
            if root_device:
                crypt_status = subprocess.run(
                    ['cryptsetup', 'status', f"/dev/mapper/{root_device}"],
                    capture_output=True, text=True
                )
                if crypt_status.returncode == 0:
                    result['status'] = 'encrypted'
                    result['method'] = 'LUKS'
                    result['details'] = {
                        'device': root_device,
                        'status_output': crypt_status.stdout
                    }
                else:
                    result['status'] = 'not encrypted'
        
        except Exception as e:
            self.logger.warning(f"LUKS check failed: {e}")
        
        # Check for eCryptfs (home directory encryption)
        try:
            if os.path.exists('/home/.ecryptfs'):
                result['status'] = 'partial (eCryptfs)'
                result['method'] = 'eCryptfs'
                if 'details' not in result:
                    result['details'] = {}
                result['details']['ecryptfs'] = True
        except:
            pass
        
        return result

    def _check_windows_encryption(self) -> Dict[str, str]:
        """Windows-specific encryption checks"""
        result = {}
        
        # Check BitLocker status
        try:
            manage_bde = subprocess.run(
                ['manage-bde', '-status', 'C:'],
                capture_output=True, text=True, shell=True
            )
            
            if manage_bde.returncode == 0:
                output = manage_bde.stdout
                if "Conversion Status: Fully Encrypted" in output:
                    result['status'] = 'encrypted'
                    result['method'] = 'BitLocker'
                    result['details'] = {
                        'protection_status': 'on' if "Protection On" in output else 'off',
                        'percentage_encrypted': next(
                            (line.split(':')[1].strip() 
                             for line in output.split('\n') 
                             if 'Percentage Encrypted' in line), 'unknown'
                        )
                    }
                else:
                    result['status'] = 'not encrypted'
        except Exception as e:
            self.logger.warning(f"BitLocker check failed: {e}")
        
        return result

    def _check_macos_encryption(self) -> Dict[str, str]:
        """macOS-specific encryption checks"""
        result = {}
        
        # Check FileVault status
        try:
            fdesetup = subprocess.run(
                ['fdesetup', 'status'],
                capture_output=True, text=True
            )
            
            if fdesetup.returncode == 0:
                output = fdesetup.stdout.strip().lower()
                if 'filevault is on' in output:
                    result['status'] = 'encrypted'
                    result['method'] = 'FileVault'
                else:
                    result['status'] = 'not encrypted'
        except Exception as e:
            self.logger.warning(f"FileVault check failed: {e}")
        
        return result

    def _check_mounted_volumes(self) -> Dict[str, Dict[str, str]]:
        """Check encryption status of all mounted volumes"""
        volumes = {}
        
        try:
            partitions = psutil.disk_partitions(all=True)
            for part in partitions:
                try:
                    vol_info = {
                        'device': part.device,
                        'mountpoint': part.mountpoint,
                        'fstype': part.fstype,
                        'encrypted': 'unknown'
                    }
                    
                    # Add basic encryption detection
                    if part.fstype.lower() in ['crypto_luks', 'ecryptfs']:
                        vol_info['encrypted'] = 'yes'
                    elif 'encrypted' in part.opts.lower():
                        vol_info['encrypted'] = 'yes'
                    
                    volumes[part.mountpoint] = vol_info
                except Exception as e:
                    self.logger.warning(f"Failed to check volume {part.mountpoint}: {e}")
        
        except Exception as e:
            self.logger.error(f"Volume check failed: {e}")
        
        return volumes

    def check_os_updates(self) -> Dict[str, Any]:
        """Comprehensive OS update check with multiple fallbacks"""
        result = {
            'status': 'unknown',
            'current_version': platform.version(),
            'available_updates': [],
            'security_updates': [],
            'last_checked': None,
            'details': {}
        }
        
        try:
            system = platform.system().lower()
            
            if system == 'linux':
                result.update(self._check_linux_updates())
            elif system == 'windows':
                result.update(self._check_windows_updates())
            elif system == 'darwin':
                result.update(self._check_macos_updates())
            
            result['last_checked'] = datetime.utcnow().isoformat()
        except Exception as e:
            self.logger.error(f"OS update check failed: {e}")
            result['error'] = str(e)
        
        return result

    def _check_linux_updates(self) -> Dict[str, Any]:
        """Linux-specific update checks"""
        result = {}
        
        # Try package manager detection
        try:
            if os.path.exists('/etc/debian_version'):
                # Debian/Ubuntu systems
                self._run_apt_update()
                updates = subprocess.run(
                    ['apt', 'list', '--upgradable'],
                    capture_output=True, text=True
                )
                
                if updates.returncode == 0:
                    update_lines = updates.stdout.split('\n')[1:]  # Skip header
                    result['available_updates'] = [
                        line.split('/')[0] for line in update_lines if line
                    ]
                    result['status'] = 'updates available' if result['available_updates'] else 'up to date'
                    
                    # Check for security updates
                    security_updates = subprocess.run(
                        ['apt-get', '--just-print', 'upgrade'],
                        capture_output=True, text=True
                    )
                    if security_updates.returncode == 0:
                        result['security_updates'] = [
                            line.split()[1] for line in security_updates.stdout.split('\n')
                            if 'Inst' in line and 'security' in line.lower()
                        ]
            
            elif os.path.exists('/etc/redhat-release'):
                # RHEL/CentOS systems
                updates = subprocess.run(
                    ['yum', 'check-update'],
                    capture_output=True, text=True
                )
                
                if updates.returncode == 100:  # 100 means updates available
                    update_lines = updates.stdout.split('\n')[2:]  # Skip headers
                    result['available_updates'] = [
                        line.split()[0] for line in update_lines 
                        if line and not line.startswith(' ')
                    ]
                    result['status'] = 'updates available'
                elif updates.returncode == 0:
                    result['status'] = 'up to date'
                
                # Check security updates
                security_updates = subprocess.run(
                    ['yum', 'updateinfo', 'list', 'security'],
                    capture_output=True, text=True
                )
                if security_updates.returncode == 0:
                    result['security_updates'] = [
                        line.split()[1] for line in security_updates.stdout.split('\n')
                        if line and not line.startswith(' ')
                    ]
        
        except Exception as e:
            self.logger.warning(f"Package manager check failed: {e}")
        
        return result

    def _run_apt_update(self) -> None:
        """Run apt update quietly"""
        try:
            subprocess.run(
                ['apt', 'update'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
        except:
            pass

    def _check_windows_updates(self) -> Dict[str, Any]:
        """Windows-specific update checks"""
        result = {}
        
        try:
            # PowerShell command to get updates
            ps_script = """
            $UpdateSession = New-Object -ComObject Microsoft.Update.Session
            $UpdateSearcher = $UpdateSession.CreateupdateSearcher()
            $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
            
            $Updates = @()
            foreach ($Update in $SearchResult.Updates) {
                $Updates += @{
                    Title = $Update.Title
                    KB = ($Update.KBArticleIDs -join ', ')
                    IsSecurity = $Update.IsSecurity
                }
            }
            
            $Updates | ConvertTo-Json
            """
            
            updates = subprocess.run(
                ['powershell', '-Command', ps_script],
                capture_output=True, text=True, shell=True
            )
            
            if updates.returncode == 0 and updates.stdout.strip():
                update_data = json.loads(updates.stdout)
                result['available_updates'] = [
                    f"{u['Title']} (KB{u['KB']})" for u in update_data
                ]
                result['security_updates'] = [
                    f"{u['Title']} (KB{u['KB']})" for u in update_data 
                    if u['IsSecurity']
                ]
                result['status'] = 'updates available' if update_data else 'up to date'
            else:
                result['status'] = 'up to date'
        
        except Exception as e:
            self.logger.warning(f"Windows update check failed: {e}")
        
        return result

    def _check_macos_updates(self) -> Dict[str, Any]:
        """macOS-specific update checks"""
        result = {}
        
        try:
            # Check for regular updates
            updates = subprocess.run(
                ['softwareupdate', '-l'],
                capture_output=True, text=True
            )
            
            if updates.returncode == 0:
                output = updates.stdout
                if "No new software available" not in output:
                    result['status'] = 'updates available'
                    # Parse available updates
                    update_lines = [
                        line.strip() for line in output.split('\n') 
                        if line.startswith('   * ')
                    ]
                    result['available_updates'] = [
                        line[4:].split('[')[0].strip() for line in update_lines
                    ]
                else:
                    result['status'] = 'up to date'
            
            # Check for security updates separately
            security_updates = subprocess.run(
                ['softwareupdate', '--list', '--include-config-data'],
                capture_output=True, text=True
            )
            if security_updates.returncode == 0:
                output = security_updates.stdout
                security_lines = [
                    line.strip() for line in output.split('\n')
                    if 'Security' in line and '*' in line
                ]
                result['security_updates'] = [
                    line.split('[')[0].strip() for line in security_lines
                ]
        
        except Exception as e:
            self.logger.warning(f"macOS update check failed: {e}")
        
        return result

    def check_antivirus(self) -> Dict[str, Any]:
        """Comprehensive antivirus check with multiple detection methods"""
        result = {
            'status': 'unknown',
            'product': None,
            'version': None,
            'enabled': None,
            'up_to_date': None,
            'details': {}
        }
        
        try:
            system = platform.system().lower()
            
            if system == 'linux':
                # Linux typically doesn't use traditional AV
                result.update({
                    'status': 'not applicable',
                    'details': {'reason': 'Linux systems typically rely on other security mechanisms'}
                })
            elif system == 'windows':
                result.update(self._check_windows_antivirus())
            elif system == 'darwin':
                result.update(self._check_macos_antivirus())
            
        except Exception as e:
            self.logger.error(f"Antivirus check failed: {e}")
            result['error'] = str(e)
        
        return result

    def _check_windows_antivirus(self) -> Dict[str, Any]:
        """Windows-specific antivirus checks"""
        result = {}
        
        try:
            # Check Windows Defender status
            defender_status = subprocess.run(
                ['powershell', '-Command', 'Get-MpComputerStatus'],
                capture_output=True, text=True, shell=True
            )
            
            if defender_status.returncode == 0:
                output = defender_status.stdout
                result['product'] = 'Windows Defender'
                result['status'] = 'running' if 'AMServiceEnabled : True' in output else 'not running'
                result['enabled'] = 'True' in output.split('AntivirusEnabled')[1].split('\n')[0]
                result['up_to_date'] = 'True' in output.split('AntivirusSignatureAge')[1].split('\n')[0]
                result['details'] = {
                    'engine_version': next(
                        (line.split(':')[1].strip() 
                         for line in output.split('\n') 
                         if 'AMEngineVersion' in line), 'unknown'
                    ),
                    'signature_version': next(
                        (line.split(':')[1].strip() 
                         for line in output.split('\n') 
                         if 'AntivirusSignatureVersion' in line), 'unknown'
                    )
                }
            
            # Check for third-party AV
            third_party_av = subprocess.run(
                ['powershell', '-Command', 'Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct'],
                capture_output=True, text=True, shell=True
            )
            
            if third_party_av.returncode == 0 and third_party_av.stdout.strip():
                av_data = []
                for line in third_party_av.stdout.split('\n'):
                    if 'displayName' in line:
                        av_data.append({
                            'product': line.split(':')[1].strip(),
                            'state': next(
                                (l.split(':')[1].strip() 
                                 for l in third_party_av.stdout.split('\n') 
                                 if 'productState' in l), 'unknown'
                            )
                        })
                
                if av_data:
                    result['third_party'] = av_data
                    if result.get('status') != 'running':
                        # Prefer third-party AV status if Defender isn't running
                        result.update({
                            'product': av_data[0]['product'],
                            'status': 'running' if int(av_data[0]['state'], 16) & 0x1000 else 'not running'
                        })
        
        except Exception as e:
            self.logger.warning(f"Windows AV check failed: {e}")
        
        return result

    def _check_macos_antivirus(self) -> Dict[str, Any]:
        """macOS-specific antivirus checks"""
        result = {}
        
        try:
            # Check for XProtect (built-in)
            xprotect = subprocess.run(
                ['pgrep', '-x', 'XProtectService'],
                capture_output=True, text=True
            )
            
            if xprotect.returncode == 0:
                result.update({
                    'product': 'XProtect',
                    'status': 'running',
                    'details': {'type': 'Built-in malware protection'}
                })
            
            # Check for common third-party AV
            common_av = ['LittleSnitch', 'Malwarebytes', 'Norton', 'McAfee', 'Sophos']
            running_av = []
            
            for av in common_av:
                try:
                    subprocess.run(
                        ['pgrep', '-x', av],
                        capture_output=True, text=True
                    )
                    running_av.append(av)
                except:
                    continue
            
            if running_av:
                result.update({
                    'product': ', '.join(running_av),
                    'status': 'running',
                    'details': {'products_found': running_av}
                })
            elif 'product' not in result:
                result['status'] = 'not running'
        
        except Exception as e:
            self.logger.warning(f"macOS AV check failed: {e}")
        
        return result

    def check_sleep_settings(self) -> Dict[str, Any]:
        """Comprehensive sleep settings check"""
        result = {
            'display_sleep': 'unknown',
            'system_sleep': 'unknown',
            'hibernate_mode': 'unknown',
            'recommended': '≤10 minutes',
            'details': {}
        }
        
        try:
            system = platform.system().lower()
            
            if system == 'linux':
                result.update(self._check_linux_sleep())
            elif system == 'windows':
                result.update(self._check_windows_sleep())
            elif system == 'darwin':
                result.update(self._check_macos_sleep())
            
            # Evaluate if settings meet security requirements
            try:
                display_sleep = int(result['display_sleep'].split()[0])
                system_sleep = int(result['system_sleep'].split()[0])
                result['meets_recommendation'] = (
                    display_sleep <= 10 and system_sleep <= 10
                )
            except:
                result['meets_recommendation'] = 'unknown'
        
        except Exception as e:
            self.logger.error(f"Sleep settings check failed: {e}")
            result['error'] = str(e)
        
        return result

    def _check_linux_sleep(self) -> Dict[str, Any]:
        """Linux-specific sleep settings check"""
        result = {}
        
        try:
            # Try GNOME settings
            gnome_sleep = subprocess.run(
                ['gsettings', 'get', 'org.gnome.settings-daemon.plugins.power', 'sleep-inactive-ac-timeout'],
                capture_output=True, text=True
            )
            
            if gnome_sleep.returncode == 0:
                timeout = gnome_sleep.stdout.strip()
                if timeout.isdigit():
                    result['system_sleep'] = f"{timeout} minutes"
                else:
                    result['system_sleep'] = 'not set'
            
            # Try systemd logind.conf
            if os.path.exists('/etc/systemd/logind.conf'):
                with open('/etc/systemd/logind.conf') as f:
                    for line in f:
                        if line.startswith('IdleAction='):
                            result['action'] = line.split('=')[1].strip()
                        elif line.startswith('IdleActionSec='):
                            seconds = int(line.split('=')[1].strip())
                            result['system_sleep'] = f"{seconds // 60} minutes"
        
        except Exception as e:
            self.logger.warning(f"Linux sleep check failed: {e}")
        
        return result

    def _check_windows_sleep(self) -> Dict[str, Any]:
        """Windows-specific sleep settings check"""
        result = {}
        
        try:
            # Check power settings
            powercfg = subprocess.run(
                ['powercfg', '/q'],
                capture_output=True, text=True, shell=True
            )
            
            if powercfg.returncode == 0:
                output = powercfg.stdout
                # Parse for sleep settings (simplified)
                sleep_lines = [
                    line.strip() for line in output.split('\n')
                    if 'Sleep' in line or 'Standby' in line
                ]
                
                for line in sleep_lines:
                    if 'AC Setting' in line:
                        if 'Sleep' in line:
                            result['system_sleep'] = line.split('Index:')[1].split()[0] + ' minutes'
                        elif 'Video' in line:
                            result['display_sleep'] = line.split('Index:')[1].split()[0] + ' minutes'
                
                # Check hibernate
                hibernate = subprocess.run(
                    ['powercfg', '/a'],
                    capture_output=True, text=True, shell=True
                )
                if hibernate.returncode == 0:
                    result['hibernate_mode'] = (
                        'enabled' if 'Hibernation has not been enabled' not in hibernate.stdout 
                        else 'disabled'
                    )
        
        except Exception as e:
            self.logger.warning(f"Windows sleep check failed: {e}")
        
        return result

    def _check_macos_sleep(self) -> Dict[str, Any]:
        """macOS-specific sleep settings check"""
        result = {}
        
        try:
            # Check pmset settings
            pmset = subprocess.run(
                ['pmset', '-g'],
                capture_output=True, text=True
            )
            
            if pmset.returncode == 0:
                output = pmset.stdout
                for line in output.split('\n'):
                    if 'sleep' in line:
                        result['system_sleep'] = f"{line.split()[1]} minutes"
                    elif 'displaysleep' in line:
                        result['display_sleep'] = f"{line.split()[1]} minutes"
                    elif 'hibernatemode' in line:
                        result['hibernate_mode'] = line.split()[1]
        
        except Exception as e:
            self.logger.warning(f"macOS sleep check failed: {e}")
        
        return result

    def collect_data(self) -> Dict[str, Any]:
        """Collect all system health data with comprehensive metadata"""
        return {
            'metadata': {
                'timestamp': datetime.utcnow().isoformat(),
                'machine_id': self.machine_id,
                'utility_version': '1.0.0',
                'collection_time_ms': None  # Will be set after collection
            },
            'system': {
                'os': {
                    'type': platform.system(),
                    'version': platform.version(),
                    'release': platform.release(),
                    'architecture': platform.machine(),
                    'update_status': self.check_os_updates()
                },
                'hardware': {
                    'processor': platform.processor(),
                    'physical_cores': psutil.cpu_count(logical=False),
                    'total_cores': psutil.cpu_count(logical=True),
                    'memory_gb': round(psutil.virtual_memory().total / (1024**3), 2)
                }
            },
            'security': {
                'disk_encryption': self.check_disk_encryption(),
                'antivirus': self.check_antivirus(),
                'sleep_settings': self.check_sleep_settings()
            },
            'resource_usage': {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': {
                    mount.mountpoint: {
                        'total_gb': round(usage.total / (1024**3), 2),
                        'used_gb': round(usage.used / (1024**3), 2),
                        'free_gb': round(usage.free / (1024**3), 2),
                        'percent': usage.percent
                    }
                    for mount, usage in (
                        (mount, psutil.disk_usage(mount.mountpoint))
                        for mount in psutil.disk_partitions()
                        if mount.fstype and os.path.exists(mount.mountpoint)
                    )
                }
            }
        }

    def has_changed(self, new_data: Dict[str, Any]) -> bool:
        """Comprehensive change detection with configurable thresholds"""
        if not self.last_report:
            return True
        
        # Compare critical security fields
        security_fields = [
            ('security.disk_encryption.status', 'exact'),
            ('security.antivirus.status', 'exact'),
            ('security.sleep_settings.meets_recommendation', 'exact'),
            ('system.os.update_status.status', 'exact')
        ]
        
        for field, comparison_type in security_fields:
            old_val = self._nested_get(self.last_report, field.split('.'))
            new_val = self._nested_get(new_data, field.split('.'))
            
            if old_val != new_val:
                self.logger.info(f"Change detected in {field}: {old_val} -> {new_val}")
                return True
        
        # Check for significant resource changes
        resource_fields = [
            ('resource_usage.cpu_percent', 10),  # 10% change threshold
            ('resource_usage.memory_percent', 5)  # 5% change threshold
        ]
        
        for field, threshold in resource_fields:
            old_val = self._nested_get(self.last_report, field.split('.'))
            new_val = self._nested_get(new_data, field.split('.'))
            
            if abs(old_val - new_val) > threshold:
                self.logger.info(f"Significant change in {field}: {old_val} -> {new_val}")
                return True
        
        return False

    def _nested_get(self, data: Dict[str, Any], keys: list) -> Any:
        """Safely get nested dictionary values"""
        for key in keys:
            try:
                data = data[key]
            except (KeyError, TypeError):
                return None
        return data

    def send_report(self, data: Dict[str, Any]) -> bool:
        """Robust report sending with retries and backoff"""
        max_retries = int(self.config['api']['retry_attempts'])
        timeout = int(self.config['api']['timeout_seconds'])
        
        for attempt in range(max_retries):
            try:
                self.resource_watchdog.check_resources()
                
                start_time = time.time()
                response = requests.post(
                    self.config['api']['endpoint'],
                    json=data,
                    headers={
                        'Content-Type': 'application/json',
                        'User-Agent': f'SystemHealthMonitor/1.0 ({platform.system()})'
                    },
                    timeout=timeout
                )
                
                data['metadata']['collection_time_ms'] = int((time.time() - start_time) * 1000)
                
                if response.status_code == 200:
                    return True
                
                self.logger.warning(
                    f"API request failed (attempt {attempt + 1}): "
                    f"HTTP {response.status_code}"
                )
                
            except requests.exceptions.RequestException as e:
                self.logger.warning(
                    f"API connection failed (attempt {attempt + 1}): {str(e)}"
                )
            
            if attempt < max_retries - 1:
                backoff = min(2 ** attempt, 30)  # Exponential backoff, max 30s
                time.sleep(backoff)
        
        return False

    def run_daemon(self) -> None:
        """Main daemon loop with comprehensive monitoring"""
        interval = int(self.config['general']['interval_minutes']) * 60
        
        self.logger.info("Starting system health monitor daemon")
        
        while not self.shutdown_flag:
            try:
                self.logger.debug("Starting system health check")
                
                # Collect data
                current_data = self.collect_data()
                
                # Check for changes
                if self.has_changed(current_data):
                    self.logger.info("System state changed - preparing report")
                    
                    # Send report
                    success = self.send_report(current_data)
                    
                    if success:
                        self.last_report = current_data
                        self.logger.info(
                            f"Report successfully sent at {current_data['metadata']['timestamp']}"
                        )
                    else:
                        self.logger.error("Failed to send report after retries")
                
                # Sleep until next interval or shutdown signal
                self.logger.debug(f"Sleeping for {interval} seconds")
                for _ in range(interval):
                    if self.shutdown_flag:
                        break
                    time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Unexpected error in daemon loop: {e}")
                time.sleep(60)  # Prevent tight error loops
        
        self.logger.info("System health monitor daemon stopped")

class ResourceWatchdog:
    """Monitors and limits resource usage of the utility"""
    
    def __init__(self, max_cpu: float = 2.0, max_memory: float = 50.0):
        self.max_cpu = max_cpu  # Percentage
        self.max_memory = max_memory  # Megabytes
        self.process = psutil.Process(os.getpid())
    
    def check_resources(self) -> None:
        """Check if we're exceeding resource limits"""
        cpu_percent = self.process.cpu_percent(interval=0.1)
        memory_mb = self.process.memory_info().rss / (1024 * 1024)
        
        if cpu_percent > self.max_cpu:
            raise ResourceWarning(
                f"CPU usage exceeded limit: {cpu_percent}% > {self.max_cpu}%"
            )
        
        if memory_mb > self.max_memory:
            raise ResourceWarning(
                f"Memory usage exceeded limit: {memory_mb:.2f}MB > {self.max_memory}MB"
            )

if __name__ == '__main__':
    monitor = SystemHealthMonitor()
    monitor.run_daemon()