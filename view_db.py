
import sqlite3
import pandas as pd
from database import ThreatDatabase


def print_table(title, data, columns):
    """Print data in a clean bordered table format."""
    print(f"\n  {title}")
    print(f"  {'=' * len(title)}")

    if not data:
        print("  (empty)\n")
        return

    df = pd.DataFrame(data)[columns]

    # Rename columns for display
    display_names = {
        'id': 'ID',
        'input_data': 'Input',
        'threat_status': 'Status',
        'threat_level': 'Level',
        'timestamp': 'Timestamp'
    }
    df = df.rename(columns=display_names)

    # Calculate column widths
    headers = list(df.columns)
    col_widths = []
    for h in headers:
        max_val = max(df[h].astype(str).str.len().max(), len(h))
        col_widths.append(max_val + 2)

    # Build separator and format row
    sep = "  +" + "+".join("-" * w for w in col_widths) + "+"
    def fmt_row(values):
        cells = []
        for val, w in zip(values, col_widths):
            cells.append(f" {str(val):<{w - 1}}")
        return "  |" + "|".join(cells) + "|"

    # Print table
    print(sep)
    print(fmt_row(headers))
    print(sep)
    for _, row in df.iterrows():
        print(fmt_row(row.values))
    print(sep)
    print(f"  Total: {len(df)} record(s)\n")


def view_database():
    print()
    print("  " + "=" * 56)
    print("         CYBER THREAT DATABASE VIEWER")
    print("  " + "=" * 56)

    db = ThreatDatabase()

    cols = ['id', 'input_data', 'threat_status', 'threat_level', 'timestamp']

    print_table("FILES", db.get_threats_by_type('FILE'), cols)
    print_table("URLs", db.get_threats_by_type('URL'), cols)
    print_table("PHONES", db.get_threats_by_type('PHONE'), cols)

    db.close()

    print("  " + "=" * 56)
    print("         END OF DATABASE VIEW")
    print("  " + "=" * 56)
    print()


if __name__ == "__main__":
    view_database()
