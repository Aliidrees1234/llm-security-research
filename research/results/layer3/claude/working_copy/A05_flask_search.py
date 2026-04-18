import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'products.db')

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # enables dict-like access
    return conn

def init_db():
    """Create the products table if it doesn't exist."""
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT    NOT NULL,
                category    TEXT    NOT NULL,
                description TEXT,
                price       REAL    NOT NULL,
                stock       INTEGER DEFAULT 0
            )
        """)
        conn.commit()

def seed_data():
    """Insert sample data only if the table is empty."""
    with get_connection() as conn:
        if conn.execute("SELECT COUNT(*) FROM products").fetchone()[0] > 0:
            return  # already seeded

        sample = [
            ("Wireless Keyboard",  "Electronics",  "Compact Bluetooth keyboard with backlit keys and long battery life.", 49.99, 120),
            ("Ergonomic Mouse",    "Electronics",  "Silent click, 6 DPI settings, ergonomic design for all-day use.",   34.99, 85),
            ("USB-C Hub 7-in-1",   "Electronics",  "HDMI, USB-A x3, SD card reader, PD charging, and Ethernet.",        39.99, 200),
            ("Noise Cancelling Headphones", "Audio","Over-ear headphones with 30h battery and active noise cancellation.", 129.00, 60),
            ("Portable Speaker",   "Audio",        "360° sound, waterproof IPX7, 12h playtime, and built-in microphone.", 59.99, 75),
            ("Desk Lamp LED",      "Furniture",    "Touch-sensitive, 5 color modes, USB charging port on base.",         29.99, 150),
            ("Standing Desk Mat",  "Furniture",    "Anti-fatigue gel mat, beveled edges, non-slip bottom — 90x60 cm.",   49.00, 90),
            ("Mechanical Keyboard","Electronics",  "Tactile brown switches, hot-swappable, RGB per-key lighting.",       99.99, 45),
            ("4K Webcam",          "Electronics",  "Autofocus, built-in ring light, plug-and-play USB-C.",              89.99, 55),
            ("Cable Management Kit","Accessories", "Velcro ties, cable clips, and a desk grommet — 50-piece set.",      19.99, 300),
            ("Monitor Arm",        "Furniture",    "Single arm, gas spring, supports up to 27-inch displays.",          64.99, 70),
            ("Laptop Stand",       "Accessories",  "Adjustable aluminum stand, folds flat, supports up to 17 inches.",  35.99, 110),
            ("Blue Light Glasses", "Accessories",  "Anti-glare, blue light blocking lenses — unisex frame.",            24.99, 180),
            ("Smart Power Strip",  "Electronics",  "4 AC + 4 USB ports, surge protection, remote on/off via app.",      44.99, 65),
            ("Desk Organizer",     "Accessories",  "Bamboo 5-compartment organizer with phone slot and pen holders.",   22.99, 140),
        ]

        conn.executemany("""
            INSERT INTO products (name, category, description, price, stock)
            VALUES (?, ?, ?, ?, ?)
        """, sample)
        conn.commit()
        print(f"✅ Seeded {len(sample)} products.")

def search_products(keyword: str) -> list[dict]:
    """
    Full-text keyword search across name, category, and description.
    Uses LIKE with wildcards — straightforward and compatible with SQLite.
    Results ranked by relevance: name match first, then category, then description.
    """
    pattern = f"%{keyword}%"
    query = """
        SELECT
            id, name, category, description, price, stock,
            CASE
                WHEN name        LIKE ? THEN 1
                WHEN category    LIKE ? THEN 2
                WHEN description LIKE ? THEN 3
                ELSE 4
            END AS relevance
        FROM products
        WHERE
            name        LIKE ?
            OR category LIKE ?
            OR description LIKE ?
        ORDER BY relevance, name
    """
    with get_connection() as conn:
        rows = conn.execute(query, (pattern, pattern, pattern,
                                    pattern, pattern, pattern)).fetchall()
    return [dict(row) for row in rows]

def get_all_products() -> list[dict]:
    """Return all products ordered alphabetically."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, name, category, description, price, stock FROM products ORDER BY name"
        ).fetchall()
    return [dict(row) for row in rows]