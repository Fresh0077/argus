import AppFooter from './components/AppFooter';
import AppHeader from './components/AppHeader';
import ScanPage from './pages/ScanPage';

/** 应用外壳：品牌栏 + 主工作区 + 页脚说明。 */
export default function App() {
  return (
    <div className="app-shell">
      <AppHeader />
      <main className="app-main">
        <ScanPage />
      </main>
      <AppFooter />
    </div>
  );
}
