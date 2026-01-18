// Tab switching
function initTabs() {
  const tabButtons = document.querySelectorAll('.tab-button');
  const tabPanels = document.querySelectorAll('.download-tab');

  if (tabButtons.length === 0) return;

  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabId = button.dataset.tab;

      tabButtons.forEach(btn => btn.classList.remove('active', 'text-gray-900', 'dark:text-gray-100'));
      tabButtons.forEach(btn => btn.classList.add('text-gray-500'));
      button.classList.add('active', 'text-gray-900', 'dark:text-gray-100');
      button.classList.remove('text-gray-500');

      tabPanels.forEach(panel => panel.classList.remove('active'));
      document.getElementById(`tab-${tabId}`).classList.add('active');
    });
  });
}

// Copy to clipboard
function initCopyButtons() {
  const copyButtons = document.querySelectorAll('.copy-btn');

  if (copyButtons.length === 0) return;

  copyButtons.forEach(button => {
    button.addEventListener('click', async () => {
      const command = button.dataset.command;
      await navigator.clipboard.writeText(command);
      button.classList.add('copied');
      button.innerHTML = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>';
      setTimeout(() => {
        button.classList.remove('copied');
        button.innerHTML = '<svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg>';
      }, 2000);
    });
  });
}

// Animated terminal typing (home page only)
function initAnimatedTerminal() {
  const commandElement = document.getElementById('animated-command');

  if (!commandElement) return;

  const commands = [
    'secrt send token.yaml coworker@example.com',
    'secrt send api-key.txt teammate@company.io',
    'gentoken | secrt send user@work.com',
    'secrt send .env dev@startup.co',
    'screencapture -i -o - | secrt send bob@example.com',
    'secrt send id_rsa peer@example.com',
    'secrt send license.key housemate@home.net',
    'echo "hi bob!" | secrt send bob@example.com',
    'secrt send credentials.json alice@example.com',
    'secrt send db-password.txt ops@infra.io',
    'secrt send cert.pem bob@company.com',
    'secrt send session.cookie friend@example.org',
    'secrt send connection-string.txt admin@service.io',
  ];

  let commandIndex = 0;

  async function typeCommand(text) {
    commandElement.textContent = '';
    for (let i = 0; i < text.length; i++) {
      commandElement.textContent += text[i];
      await new Promise(resolve => setTimeout(resolve, Math.random() * 35));
    }
  }

  async function animateCommands() {
    while (true) {
      await typeCommand(commands[commandIndex]);
      await new Promise(resolve => setTimeout(resolve, 2000));
      commandIndex = (commandIndex + 1) % commands.length;
    }
  }

  animateCommands();
}

// Initialize all components
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initCopyButtons();
  initAnimatedTerminal();
});
