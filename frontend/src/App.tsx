import { BrowserRouter, Route, Routes } from "react-router-dom";

import { NewProject } from "./pages/NewProject";
import { ProjectsList } from "./pages/ProjectsList";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<ProjectsList />} />
        <Route path="/projects/new" element={<NewProject />} />
      </Routes>
    </BrowserRouter>
  );
}
