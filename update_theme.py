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

        # Update Brand
        content = content.replace('NEURAL_SYNTH', 'Bug Hunter')

        # Update Fonts
        content = content.replace('Lexend', 'Rajdhani')
        content = content.replace('Inter', 'Share Tech Mono')
        content = content.replace('font-lexend', 'font-rajdhani')
        
        # Update colors - primary (purple -> neon green)
        content = content.replace('#db90ff', '#00ff41')
        content = content.replace('#d37bff', '#00ff41')
        content = content.replace('219, 144, 255', '0, 255, 65')
        content = content.replace('219,144,255', '0,255,65')
        
        # Update Tailwind text/gradient colors
        content = content.replace('from-purple-400', 'from-green-400')
        content = content.replace('to-fuchsia-500', 'to-emerald-500')
        content = content.replace('text-purple-400', 'text-green-500')
        content = content.replace('from-purple-500', 'from-green-500')
        content = content.replace('via-fuchsia-500', 'via-emerald-500')
        content = content.replace('to-purple-500', 'to-green-500')
        
        # Update colors - secondary (pink/red -> cyan)
        content = content.replace('#ff6f7c', '#00e5ff')
        content = content.replace('255, 111, 124', '0, 229, 255')
        content = content.replace('255,111,124', '0,229,255')
        
        # Update background
        content = content.replace('#0c0e12', '#050505')
        
        # Ensure we have neon cyberpunk style styling where needed
        content = content.replace('font-family: \'Share Tech Mono\'', 'font-family: \'Share Tech Mono\', monospace')
        content = content.replace('font-family: \'Rajdhani\'', 'font-family: \'Rajdhani\', sans-serif')
        content = content.replace('.font-rajdhani {', '.font-rajdhani {\n            font-family: \'Rajdhani\', sans-serif;\n        }')
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Updated {file_path}")
    else:
        print(f"Skipped {file_path} (does not exist)")
