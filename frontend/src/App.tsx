import { BrowserRouter, Route, Routes } from "react-router-dom";

import { NewProject } from "./pages/NewProject";
import { ProjectDetail } from "./pages/ProjectDetail";
import { ProjectsList } from "./pages/ProjectsList";
import { ScanReport } from "./pages/ScanReport";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<ProjectsList />} />
        <Route path="/projects/new" element={<NewProject />} />
        <Route path="/projects/:id" element={<ProjectDetail />} />
        <Route path="/scans/:id" element={<ScanReport />} />
      </Routes>
    </BrowserRouter>
  );
}
