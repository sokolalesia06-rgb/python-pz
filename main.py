import hashlib

def analyze_log_file(log_file_path):
    results = {}

    try:
        with open(log_file_path, "r") as file:
            for line in file:
                parts = line.split()
                if len(parts) < 9:
                    continue

                status_code = parts[8]

                if status_code.isdigit():
                    results[status_code] = results.get(status_code, 0) + 1

    except FileNotFoundError:
        print(f"[Помилка] Файл не знайдено: {log_file_path}")
    except IOError:
        print(f"[Помилка] Помилка читання файлу: {log_file_path}")

    return results

def generate_file_hashes(*file_paths):
    hashes = {}

    for path in file_paths:
        try:
            with open(path, "rb") as f:
                data = f.read()
                file_hash = hashlib.sha256(data).hexdigest()
                hashes[path] = file_hash

        except FileNotFoundError:
            print(f"[Помилка] Файл не знайдено: {path}")
        except IOError:
            print(f"[Помилка] Помилка читання файлу: {path}")

    return hashes

def filter_ips(input_file_path, output_file_path, allowed_ips):
    counter = {}

    try:
        with open(input_file_path, "r") as file:
            for line in file:
                parts = line.split()
                if len(parts) < 1:
                    continue

                ip = parts[0]

                if ip in allowed_ips:
                    counter[ip] = counter.get(ip, 0) + 1

        with open(output_file_path, "w") as out:
            for ip, count in counter.items():
                out.write(f"{ip}: {count}\n")

    except FileNotFoundError:
        print(f"[Помилка] Вхідний файл не знайдено: {input_file_path}")
    except IOError:
        print(f"[Помилка] Помилка роботи з файлами")

if __name__ == "__main__":
    log_path = "apache_logs.txt"

    print("=== Завдання 1 ===")
    stats = analyze_log_file(log_path)
    print(stats)

    print("\n=== Завдання 2 ===")
    hashes = generate_file_hashes(log_path)
    print(hashes)

    print("\n=== Завдання 3 ===")
    allowed = ["83.149.9.216", "93.114.45.13"]
    filter_ips("apache_logs.txt", "filtered_ips.txt", allowed)
    print("Файл 'filtered_ips.txt' створено.")
