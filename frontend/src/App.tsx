import { BrowserRouter, Route, Routes } from "react-router-dom";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<div>Recon Platform</div>} />
      </Routes>
    </BrowserRouter>
  );
}
