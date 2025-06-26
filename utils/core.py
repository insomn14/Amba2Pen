import re

def parse_status_codes(status_code_arg):
    """
    Parse status code filter argument and return a list of valid status codes.
    
    Args:
        status_code_arg (str): Status code filter string (e.g., '200,400,404' or '4xx,5xx')
    
    Returns:
        list: List of status codes to filter, or None if all should be shown
    """
    if not status_code_arg:
        return None
    
    status_codes = []
    parts = status_code_arg.split(',')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
            
        # Handle range patterns like '4xx', '5xx'
        if re.match(r'^\dxx$', part):
            start_code = int(part[0]) * 100
            end_code = start_code + 99
            status_codes.extend(range(start_code, end_code + 1))
        # Handle specific status codes
        elif part.isdigit():
            status_codes.append(int(part))
        else:
            print(f"Warning: Invalid status code format '{part}'. Skipping.")
    
    return status_codes if status_codes else None

def should_display_status_code(status_code, status_code_filter):
    """
    Check if a status code should be displayed based on the filter.
    
    Args:
        status_code (int): The status code to check
        status_code_filter (list): List of status codes to show, or None for all
    
    Returns:
        bool: True if status code should be displayed, False otherwise
    """
    if status_code_filter is None:
        return True
    return status_code in status_code_filter
