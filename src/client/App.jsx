import React from 'react';
import ReactDOM from 'react-dom';
import Sidebar from './components/Sidebar';
import Settings from './components/Settings';

/**
 * Main App component
 * Determines which view to render based on the page
 */
const App = () => {
  // Check which page we're on based on the window location or a parameter
  const urlParams = new URLSearchParams(window.location.search);
  const view = urlParams.get('view') || 'sidebar';

  if (view === 'settings') {
    return <Settings />;
  }

  return <Sidebar />;
};

// Render the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  ReactDOM.render(<App />, document.getElementById('root'));
});

export default App;
