import os

files_to_update = [
    '/home/hari/Desktop/Bug Bounty/dashboard.html',
    '/home/hari/Desktop/Bug Bounty/bugbounty_backend/templates/dashboard.html',
    '/home/hari/Desktop/Bug Bounty/bugbounty_backend/app/templates/dashboard.html'
]

for file_path in files_to_update:
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()

        content = content.replace('card-Share Tech Monoaction', 'card-interaction')
        content = content.replace('setShare Tech Monoval', 'setInterval')
        content = content.replace('clearShare Tech Monoval', 'clearInterval')
        content = content.replace('poShare Tech Monoter', 'pointer')
        content = content.replace('Share Tech Monoaction', 'interaction')
        content = content.replace('Share Tech Monoface', 'interface')
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed {file_path}")
