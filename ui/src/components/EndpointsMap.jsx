import React, { useState, useEffect, useRef, useMemo } from 'react';
import axios from 'axios';

/**
 * EndpointsMap - Premium Force-Directed Cyber Attack Surface Graph.
 * Visualizes targets, endpoints, parameter structures, and live security findings
 * with particle flow animations, glowing bloom, and interactive node inspection.
 */
function EndpointsMap({ targetId, monitor }) {
  const canvasRef = useRef(null);
  const containerRef = useRef(null);
  
  // Graph Data States
  const [nodes, setNodes] = useState([]);
  const [links, setLinks] = useState([]);
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchQuery, setSearchQuery] = useState('');
  
  // Filter and Control States
  const [showParams, setShowParams] = useState(true);
  const [showFindingsOnly, setShowFindingsOnly] = useState(false);
  const [showJsFiles, setShowJsFiles] = useState(true);
  const [isPhysicsActive, setIsPhysicsActive] = useState(true);
  const [repulsionStrength, setRepulsionStrength] = useState(160);
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [isFullscreen, setIsFullscreen] = useState(false);
  
  // Canvas View States
  const transformRef = useRef({ x: 0, y: 0, scale: 1 });
  const mouseRef = useRef({ x: 0, y: 0, isDown: false, dragStart: { x: 0, y: 0 } });
  const draggedNodeRef = useRef(null);
  const hoveredNodeRef = useRef(null);
  const animationFrameRef = useRef(null);
  const timeRef = useRef(0);
  
  // ---------------------------------------------------------------------------
  // 1. Data Collection & Graph Construction
  // ---------------------------------------------------------------------------
  useEffect(() => {
    let active = true;
    
    async function buildGraph() {
      let rawEndpoints = [];
      let rawParams = [];
      let rawFindings = [];
      let targetUrl = "Target Domain";

      if (monitor) {
        targetUrl = monitor.target?.base_url || "Target Scope";
        
        const endpointMap = new Map();
        const paramMap = new Map();
        
        (monitor.recent_checks || []).forEach(check => {
          let cleanUrl = check.endpoint_url || '';
          try {
            const parsed = new URL(cleanUrl);
            cleanUrl = `${parsed.origin}${parsed.pathname}`;
          } catch {}
          if (cleanUrl.length > 1 && cleanUrl.endsWith('/')) {
            cleanUrl = cleanUrl.slice(0, -1);
          }
          const method = (check.endpoint_method || 'GET').toUpperCase();
          const epKey = `${method} ${cleanUrl}`;
          if (!endpointMap.has(epKey)) {
            endpointMap.set(epKey, {
              id: `ep-${cleanUrl.replace(/[^a-zA-Z0-9]/g, '_')}`,
              method: method,
              url_pattern: cleanUrl,
              type: 'endpoint'
            });
          }
          
          if (check.param_name) {
            const pName = String(check.param_name).trim();
            const pLoc = (check.param_location || 'query').toLowerCase();
            const paramKey = `${epKey} - ${pName}:${pLoc}`;
            if (!paramMap.has(paramKey)) {
              paramMap.set(paramKey, {
                id: `param-${cleanUrl.replace(/[^a-zA-Z0-9]/g, '_')}-${pName}-${pLoc}`,
                endpointKey: epKey,
                name: pName,
                location: pLoc,
                type: 'param'
              });
            }
          }
        });
        
        rawEndpoints = Array.from(endpointMap.values());
        rawParams = Array.from(paramMap.values());
        rawFindings = (monitor.recent_findings || []).map((f, idx) => ({
          id: `finding-${f.id || idx}`,
          endpoint_url: f.endpoint_url,
          param_name: f.param_name,
          severity: f.severity || 'high',
          vuln_type: f.vuln_type || 'xss',
          payload: f.payload_preview || f.payload || '',
          type: 'finding'
        }));
      } else if (targetId) {
        try {
          const epRes = await axios.get(`/api/v1/endpoints?target_id=${targetId}`);
          const fetchedEndpoints = epRes.data || [];
          
          // Deduplicate endpoints by method + normalized path
          const dedupedEpMap = new Map();
          fetchedEndpoints.forEach(ep => {
            let cleanUrl = ep.url_pattern || '';
            try {
              const parsed = new URL(cleanUrl);
              cleanUrl = `${parsed.origin}${parsed.pathname}`;
            } catch {}
            if (cleanUrl.length > 1 && cleanUrl.endsWith('/')) {
              cleanUrl = cleanUrl.slice(0, -1);
            }
            const method = (ep.method || 'GET').toUpperCase();
            const epKey = `${method} ${cleanUrl}`;
            if (!dedupedEpMap.has(epKey)) {
              dedupedEpMap.set(epKey, {
                ...ep,
                id: ep.id,
                method: method,
                url_pattern: cleanUrl,
              });
            }
          });
          rawEndpoints = Array.from(dedupedEpMap.values());
          
          const paramPromises = rawEndpoints.map(ep => 
            axios.get(`/api/v1/params?endpoint_id=${ep.id}`).then(res => 
              (res.data || []).map(p => ({ ...p, endpointKey: `${ep.method} ${ep.url_pattern}` }))
            ).catch(() => [])
          );
          const paramsList = await Promise.all(paramPromises);
          const flatParams = paramsList.flat();
          
          // Deduplicate params
          const dedupedParamMap = new Map();
          flatParams.forEach(p => {
            const pKey = `${p.endpointKey} - ${p.name}:${p.location || 'query'}`;
            if (!dedupedParamMap.has(pKey)) {
              dedupedParamMap.set(pKey, p);
            }
          });
          rawParams = Array.from(dedupedParamMap.values());
          
          if (rawEndpoints.length > 0) {
            try {
              const parsed = new URL(rawEndpoints[0].url_pattern);
              targetUrl = parsed.origin;
            } catch {
              targetUrl = rawEndpoints[0].url_pattern;
            }
          }
        } catch (error) {
          console.error("Failed to build endpoints graph:", error);
        }
      } else {
        return;
      }

      if (!active) return;

      const newNodes = [];
      const newLinks = [];
      
      // A. Center Root Target Node
      const rootId = 'root-target';
      newNodes.push({
        id: rootId,
        label: targetUrl,
        type: 'target',
        radius: 22,
        color: '#8b5cf6',
        x: 0, y: 0, vx: 0, vy: 0
      });
      
      // B. Filter & Add Endpoint Nodes
      const validEpKeys = new Set();
      rawEndpoints.forEach((ep, idx) => {
        const isJs = (ep.url_pattern || '').split('?')[0].endsWith('.js');
        if (!showJsFiles && isJs) return;
        
        if (showFindingsOnly) {
          const hasFinding = rawFindings.some(f => f.endpoint_url === ep.url_pattern);
          if (!hasFinding) return;
        }
        
        const epKey = `${ep.method} ${ep.url_pattern}`;
        validEpKeys.add(epKey);
        
        const method = (ep.method || 'GET').toUpperCase();
        let epColor = '#38bdf8'; // Sky blue GET
        if (method === 'POST') epColor = '#f43f5e'; // Rose POST
        else if (method === 'PUT' || method === 'PATCH') epColor = '#a855f7'; // Purple PUT
        else if (method === 'DELETE') epColor = '#ef4444'; // Red DELETE
        
        const angle = (idx / Math.max(rawEndpoints.length, 1)) * 2 * Math.PI;
        const initialDist = 130 + (idx % 3) * 25;
        
        newNodes.push({
          id: `ep-${ep.id || idx}`,
          label: ep.url_pattern,
          method: method,
          type: 'endpoint',
          radius: 14,
          color: epColor,
          x: Math.cos(angle) * initialDist,
          y: Math.sin(angle) * initialDist,
          vx: 0, vy: 0
        });
        
        newLinks.push({
          source: rootId,
          target: `ep-${ep.id || idx}`,
          length: 130,
          color: 'rgba(139, 92, 246, 0.25)',
          flowSpeed: 0.008
        });
      });
      
      // C. Filter & Add Parameter Nodes
      if (showParams) {
        rawParams.forEach((param, idx) => {
          const epNode = rawEndpoints.find(e => `${e.method} ${e.url_pattern}` === param.endpointKey);
          if (!epNode || !validEpKeys.has(param.endpointKey)) return;
          
          const epNodeId = `ep-${epNode.id || ''}`;
          const createdEpNode = newNodes.find(n => n.id === epNodeId);
          const refX = createdEpNode ? createdEpNode.x : 0;
          const refY = createdEpNode ? createdEpNode.y : 0;
          
          const paramNodeId = `param-${param.id || idx}`;
          newNodes.push({
            id: paramNodeId,
            label: `${param.name} (${param.location || 'query'})`,
            name: param.name,
            location: param.location || 'query',
            type: 'param',
            radius: 8,
            color: '#fbbf24', // Amber/gold
            x: refX + (Math.random() - 0.5) * 50,
            y: refY + (Math.random() - 0.5) * 50,
            vx: 0, vy: 0
          });
          
          newLinks.push({
            source: epNodeId,
            target: paramNodeId,
            length: 65,
            color: 'rgba(251, 191, 36, 0.3)',
            flowSpeed: 0.012
          });
          
          // D. Finding Nodes connected to Parameters
          rawFindings.forEach(f => {
            if (f.endpoint_url === epNode.url_pattern && f.param_name === param.name) {
              newNodes.push({
                id: f.id,
                label: `XSS (${(f.severity || 'high').toUpperCase()})`,
                severity: f.severity,
                payload: f.payload,
                vuln_type: f.vuln_type,
                type: 'finding',
                radius: 12,
                color: '#ff2a5f',
                x: refX + (Math.random() - 0.5) * 70,
                y: refY + (Math.random() - 0.5) * 70,
                vx: 0, vy: 0
              });
              
              newLinks.push({
                source: paramNodeId,
                target: f.id,
                length: 45,
                color: 'rgba(255, 42, 95, 0.5)',
                flowSpeed: 0.018
              });
            }
          });
        });
      }
      
      const nodeMap = new Map(newNodes.map(n => [n.id, n]));
      const resolvedLinks = [];
      newLinks.forEach(link => {
        const sourceNode = nodeMap.get(link.source);
        const targetNode = nodeMap.get(link.target);
        if (sourceNode && targetNode) {
          resolvedLinks.push({ ...link, source: sourceNode, target: targetNode });
        }
      });
      
      setNodes(newNodes);
      setLinks(resolvedLinks);
    }
    
    buildGraph();
    return () => { active = false; };
  }, [targetId, monitor, showParams, showFindingsOnly, showJsFiles]);

  // ---------------------------------------------------------------------------
  // 2. Physics Simulation Loop & Canvas Rendering
  // ---------------------------------------------------------------------------
  useEffect(() => {
    if (nodes.length === 0) return;
    
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;
    const ctx = canvas.getContext('2d');
    
    const handleResize = () => {
      if (!containerRef.current || !canvasRef.current) return;
      const rect = containerRef.current.getBoundingClientRect();
      const w = Math.max(200, Math.floor(rect.width));
      const h = Math.max(300, Math.floor(rect.height || 540));
      if (canvasRef.current.width !== w || canvasRef.current.height !== h) {
        canvasRef.current.width = w;
        canvasRef.current.height = h;
      }
    };
    handleResize();
    
    let resizeObserver = null;
    if (typeof ResizeObserver !== 'undefined' && container) {
      resizeObserver = new ResizeObserver(() => {
        handleResize();
      });
      resizeObserver.observe(container);
    }
    window.addEventListener('resize', handleResize);
    
    let isRunning = true;
    
    const k_repulsion = repulsionStrength * 90;
    const k_attraction = 0.038;
    const k_gravity = 0.012;
    const damping = 0.88;
    
    function stepPhysics() {
      if (!isRunning) return;
      timeRef.current += 1;
      
      if (isPhysicsActive) {
        // A. Repulsion
        for (let i = 0; i < nodes.length; i++) {
          const nodeA = nodes[i];
          if (nodeA === draggedNodeRef.current) continue;
          
          for (let j = i + 1; j < nodes.length; j++) {
            const nodeB = nodes[j];
            const dx = nodeB.x - nodeA.x;
            const dy = nodeB.y - nodeA.y;
            let dist = Math.sqrt(dx * dx + dy * dy);
            if (dist < 14) {
              nodeA.x -= (Math.random() - 0.5) * 8;
              nodeA.y -= (Math.random() - 0.5) * 8;
              dist = 14;
            }
            
            if (dist < 450) {
              const force = k_repulsion / (dist * dist);
              const fx = (dx / dist) * force;
              const fy = (dy / dist) * force;
              
              nodeA.vx -= fx;
              nodeA.vy -= fy;
              nodeB.vx += fx;
              nodeB.vy += fy;
            }
          }
        }
        
        // B. Attraction
        links.forEach(link => {
          const dx = link.target.x - link.source.x;
          const dy = link.target.y - link.source.y;
          let dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 5) dist = 5;
          
          const force = k_attraction * (dist - link.length);
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;
          
          if (link.source !== draggedNodeRef.current && link.source.id !== 'root-target') {
            link.source.vx += fx;
            link.source.vy += fy;
          }
          if (link.target !== draggedNodeRef.current) {
            link.target.vx -= fx;
            link.target.vy -= fy;
          }
        });
        
        // C. Center Centering
        nodes.forEach(node => {
          if (node === draggedNodeRef.current || node.id === 'root-target') return;
          
          const dx = 0 - node.x;
          const dy = 0 - node.y;
          node.vx += dx * k_gravity;
          node.vy += dy * k_gravity;
          
          node.x += node.vx;
          node.y += node.vy;
          node.vx *= damping;
          node.vy *= damping;
        });
      }
      
      drawFrame();
      animationFrameRef.current = requestAnimationFrame(stepPhysics);
    }
    
    function drawFrame() {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      
      const t = transformRef.current;
      const centerX = canvas.width / 2 + t.x;
      const centerY = canvas.height / 2 + t.y;
      
      // 1. Draw Deep Cyber Grid Pattern
      ctx.save();
      const gridSize = 40 * t.scale;
      const startX = (centerX % gridSize) - gridSize;
      const startY = (centerY % gridSize) - gridSize;
      
      ctx.strokeStyle = 'rgba(255, 255, 255, 0.03)';
      ctx.lineWidth = 1;
      for (let x = startX; x < canvas.width + gridSize; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, canvas.height);
        ctx.stroke();
      }
      for (let y = startY; y < canvas.height + gridSize; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(canvas.width, y);
        ctx.stroke();
      }
      
      // Ambient Radial Center Aura
      const ambientGrad = ctx.createRadialGradient(centerX, centerY, 10, centerX, centerY, 380 * t.scale);
      ambientGrad.addColorStop(0, 'rgba(139, 92, 246, 0.08)');
      ambientGrad.addColorStop(0.5, 'rgba(56, 189, 248, 0.03)');
      ambientGrad.addColorStop(1, 'rgba(0, 0, 0, 0)');
      ctx.fillStyle = ambientGrad;
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.restore();
      
      ctx.save();
      ctx.translate(centerX, centerY);
      ctx.scale(t.scale, t.scale);
      
      const now = Date.now();
      
      // 2. Draw Links & Animated Data Packets
      links.forEach(link => {
        const isMatched = searchQuery && (
          link.source.label.toLowerCase().includes(searchQuery.toLowerCase()) ||
          link.target.label.toLowerCase().includes(searchQuery.toLowerCase())
        );
        
        ctx.save();
        ctx.beginPath();
        ctx.moveTo(link.source.x, link.source.y);
        ctx.lineTo(link.target.x, link.target.y);
        ctx.strokeStyle = isMatched ? 'rgba(56, 189, 248, 0.8)' : link.color;
        ctx.lineWidth = isMatched ? 2.2 : (link.target.type === 'finding' ? 2 : 1.2);
        ctx.stroke();
        
        // Flowing energy packet particle
        const flowProg = (timeRef.current * (link.flowSpeed || 0.01)) % 1;
        const px = link.source.x + (link.target.x - link.source.x) * flowProg;
        const py = link.source.y + (link.target.y - link.source.y) * flowProg;
        
        ctx.beginPath();
        ctx.arc(px, py, link.target.type === 'finding' ? 2.5 : 1.8, 0, 2 * Math.PI);
        ctx.fillStyle = link.target.type === 'finding' ? '#ff2a5f' : '#38bdf8';
        ctx.shadowColor = link.target.type === 'finding' ? '#ff2a5f' : '#38bdf8';
        ctx.shadowBlur = 6;
        ctx.fill();
        ctx.restore();
      });
      
      // 3. Draw Nodes with Glowing Multi-layer Rings
      nodes.forEach(node => {
        const isHovered = hoveredNodeRef.current === node;
        const isSelected = selectedNode === node;
        const isSearched = searchQuery && node.label.toLowerCase().includes(searchQuery.toLowerCase());
        
        ctx.save();
        
        // Halo & Glow Radiance
        if (node.type === 'target') {
          const ringPulse = Math.sin(now / 400) * 3;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 12 + ringPulse, 0, 2 * Math.PI);
          ctx.strokeStyle = 'rgba(139, 92, 246, 0.35)';
          ctx.lineWidth = 1.5;
          ctx.setLineDash([4, 4]);
          ctx.stroke();
          ctx.setLineDash([]);
          
          const grad = ctx.createRadialGradient(node.x, node.y, node.radius, node.x, node.y, node.radius + 25);
          grad.addColorStop(0, 'rgba(139, 92, 246, 0.35)');
          grad.addColorStop(1, 'rgba(139, 92, 246, 0)');
          ctx.fillStyle = grad;
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + 25, 0, 2 * Math.PI);
          ctx.fill();
        } else if (node.type === 'finding') {
          const pulse = 6 + Math.sin(now / 120) * 4;
          ctx.fillStyle = 'rgba(255, 42, 95, 0.25)';
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + pulse, 0, 2 * Math.PI);
          ctx.fill();
        }
        
        // Node Base Body with Radial Specular Highlight
        const baseGrad = ctx.createRadialGradient(
          node.x - node.radius * 0.3, 
          node.y - node.radius * 0.3, 
          node.radius * 0.1, 
          node.x, 
          node.y, 
          node.radius
        );
        baseGrad.addColorStop(0, '#ffffff');
        baseGrad.addColorStop(0.3, node.color);
        baseGrad.addColorStop(1, node.type === 'target' ? '#6d28d9' : (node.type === 'finding' ? '#9f1239' : '#0f172a'));
        
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius + (isHovered || isSearched ? 3 : 0), 0, 2 * Math.PI);
        ctx.fillStyle = baseGrad;
        ctx.shadowColor = node.color;
        ctx.shadowBlur = (isSelected || isHovered || isSearched) ? 16 : 8;
        ctx.fill();
        
        // Outer Crisp Border
        ctx.strokeStyle = isSelected 
          ? '#ffffff' 
          : (isSearched ? '#38bdf8' : (isHovered ? '#f8fafc' : 'rgba(255, 255, 255, 0.4)'));
        ctx.lineWidth = isSelected ? 2.5 : (isHovered ? 2 : 1.2);
        ctx.stroke();
        
        // Endpoint HTTP Method Badges
        if (node.type === 'endpoint' && node.method) {
          ctx.shadowBlur = 0;
          ctx.fillStyle = '#ffffff';
          ctx.font = 'bold 8px ui-monospace, SFMono-Regular, Menlo, monospace';
          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillText(node.method, node.x, node.y);
        }
        
        // Node Text Labels for Root Target and Vulnerabilities
        if (node.type === 'target' || node.type === 'finding' || isHovered || isSelected || isSearched) {
          ctx.shadowBlur = 4;
          ctx.shadowColor = 'rgba(0, 0, 0, 0.9)';
          ctx.fillStyle = node.type === 'finding' ? '#fecdd3' : '#e2e8f0';
          ctx.font = node.type === 'target' 
            ? 'bold 12px system-ui' 
            : (node.type === 'finding' ? 'bold 11px system-ui' : '10px system-ui');
          ctx.textAlign = 'center';
          ctx.textBaseline = 'top';
          
          let displayLabel = node.label;
          if (displayLabel.length > 34) {
            displayLabel = displayLabel.slice(0, 31) + '...';
          }
          ctx.fillText(displayLabel, node.x, node.y + node.radius + 6);
        }
        
        ctx.restore();
      });
      
      // 4. Sleek Cyber Tooltip on Hover
      if (hoveredNodeRef.current) {
        const node = hoveredNodeRef.current;
        ctx.restore();
        
        ctx.save();
        const pad = 12;
        const text = node.label;
        ctx.font = '500 11px ui-monospace, SFMono-Regular, Menlo, monospace';
        const textWidth = ctx.measureText(text).width;
        const width = Math.max(textWidth + pad * 2, 120);
        const height = 34;
        
        const screenX = (node.x * t.scale) + centerX;
        const screenY = (node.y * t.scale) + centerY;
        
        const rx = Math.max(10, Math.min(canvas.width - width - 10, screenX - width / 2));
        const ry = Math.max(10, screenY - node.radius * t.scale - height - 12);
        
        ctx.shadowColor = 'rgba(0, 0, 0, 0.6)';
        ctx.shadowBlur = 12;
        ctx.fillStyle = 'rgba(10, 15, 29, 0.95)';
        ctx.strokeStyle = node.color || 'rgba(56, 189, 248, 0.5)';
        ctx.lineWidth = 1.5;
        
        ctx.beginPath();
        ctx.roundRect(rx, ry, width, height, 8);
        ctx.fill();
        ctx.stroke();
        
        ctx.shadowBlur = 0;
        ctx.fillStyle = '#f8fafc';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(text, rx + width / 2, ry + height / 2);
        ctx.restore();
        
        ctx.save();
        ctx.translate(centerX, centerY);
        ctx.scale(t.scale, t.scale);
      }
      
      ctx.restore();
    }
    
    animationFrameRef.current = requestAnimationFrame(stepPhysics);
    
    return () => {
      isRunning = false;
      window.removeEventListener('resize', handleResize);
      if (resizeObserver) resizeObserver.disconnect();
      cancelAnimationFrame(animationFrameRef.current);
    };
  }, [nodes, links, selectedNode, repulsionStrength, isPhysicsActive, searchQuery]);

  // ---------------------------------------------------------------------------
  // 3. Mouse Interaction & Navigation Controls
  // ---------------------------------------------------------------------------
  const getMousePos = (e) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };
    const rect = canvas.getBoundingClientRect();
    return {
      x: e.clientX - rect.left,
      y: e.clientY - rect.top
    };
  };

  const toGraphCoords = (pos) => {
    const canvas = canvasRef.current;
    if (!canvas) return { x: 0, y: 0 };
    const t = transformRef.current;
    return {
      x: (pos.x - canvas.width / 2 - t.x) / t.scale,
      y: (pos.y - canvas.height / 2 - t.y) / t.scale
    };
  };

  const handleMouseDown = (e) => {
    const pos = getMousePos(e);
    const graphPos = toGraphCoords(pos);
    
    let clickedNode = null;
    for (let i = nodes.length - 1; i >= 0; i--) {
      const node = nodes[i];
      const dx = graphPos.x - node.x;
      const dy = graphPos.y - node.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < node.radius + 5) {
        clickedNode = node;
        break;
      }
    }
    
    if (clickedNode) {
      draggedNodeRef.current = clickedNode;
      setSelectedNode(clickedNode);
      setIsSidebarOpen(true);
    } else {
      mouseRef.current.isDown = true;
      mouseRef.current.dragStart = { x: pos.x - transformRef.current.x, y: pos.y - transformRef.current.y };
    }
  };

  const handleMouseMove = (e) => {
    const pos = getMousePos(e);
    const graphPos = toGraphCoords(pos);
    
    if (draggedNodeRef.current) {
      draggedNodeRef.current.x = graphPos.x;
      draggedNodeRef.current.y = graphPos.y;
      draggedNodeRef.current.vx = 0;
      draggedNodeRef.current.vy = 0;
    } else if (mouseRef.current.isDown) {
      transformRef.current.x = pos.x - mouseRef.current.dragStart.x;
      transformRef.current.y = pos.y - mouseRef.current.dragStart.y;
    } else {
      let foundHover = null;
      for (let i = nodes.length - 1; i >= 0; i--) {
        const node = nodes[i];
        const dx = graphPos.x - node.x;
        const dy = graphPos.y - node.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < node.radius + 5) {
          foundHover = node;
          break;
        }
      }
      hoveredNodeRef.current = foundHover;
    }
  };

  const handleMouseUp = () => {
    draggedNodeRef.current = null;
    mouseRef.current.isDown = false;
  };

  const handleWheel = (e) => {
    e.preventDefault();
    const pos = getMousePos(e);
    const graphPos = toGraphCoords(pos);
    
    const zoomFactor = 1.12;
    const nextScale = e.deltaY < 0 
      ? transformRef.current.scale * zoomFactor 
      : transformRef.current.scale / zoomFactor;
      
    const scale = Math.max(0.2, Math.min(3.5, nextScale));
    
    const canvas = canvasRef.current;
    if (canvas) {
      transformRef.current.x = pos.x - canvas.width / 2 - graphPos.x * scale;
      transformRef.current.y = pos.y - canvas.height / 2 - graphPos.y * scale;
      transformRef.current.scale = scale;
    }
  };

  const zoomIn = () => {
    transformRef.current.scale = Math.min(3.5, transformRef.current.scale * 1.25);
  };

  const zoomOut = () => {
    transformRef.current.scale = Math.max(0.2, transformRef.current.scale / 1.25);
  };

  const resetTransform = () => {
    transformRef.current = { x: 0, y: 0, scale: 1 };
    nodes.forEach(n => {
      if (n.id !== 'root-target') {
        n.vx = (Math.random() - 0.5) * 15;
        n.vy = (Math.random() - 0.5) * 15;
      }
    });
  };

  const endpointCount = useMemo(() => nodes.filter(n => n.type === 'endpoint').length, [nodes]);
  const paramCount = useMemo(() => nodes.filter(n => n.type === 'param').length, [nodes]);
  const findingCount = useMemo(() => nodes.filter(n => n.type === 'finding').length, [nodes]);

  // ---------------------------------------------------------------------------
  // 4. Render Layout & Node Inspector
  // ---------------------------------------------------------------------------
  return (
    <div className={`bg-carbon-900/90 border border-carbon-700/80 rounded-xl shadow-2xl overflow-hidden text-carbon-200 flex flex-col transition-all duration-200 ${
      isFullscreen ? 'fixed inset-4 z-50 h-[calc(100vh-2rem)] bg-carbon-950' : 'h-[620px]'
    }`}>
      {/* Header bar */}
      <div className="bg-carbon-850/80 backdrop-blur-md border-b border-carbon-700/80 px-4 py-3 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-brand-500/20 border border-brand-500/40 flex items-center justify-center text-brand-300 shadow-inner">
            🕸️
          </div>
          <div>
            <h2 className="text-sm font-bold text-carbon-100 flex items-center gap-2 tracking-wide">
              Live Recon Achievement Graph
              <span className="text-[10px] px-2 py-0.5 rounded-full bg-brand-500/15 border border-brand-500/30 text-brand-300 font-mono">
                CYBERNETIC TOPOLOGY
              </span>
            </h2>
            <p className="text-[11px] text-carbon-400">
              Interactive force-directed attack surface map with live packet streaming & sink tracing.
            </p>
          </div>
        </div>

        {/* Filter Controls & Action Buttons */}
        <div className="flex flex-wrap items-center gap-2.5 text-xs">
          <input
            type="text"
            placeholder="Search nodes & URLs..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="bg-carbon-950/70 border border-carbon-700/80 rounded-lg px-2.5 py-1 text-xs text-carbon-100 placeholder-carbon-500 focus:outline-none focus:border-brand-500/60 w-36 sm:w-44"
          />

          <label className="flex items-center gap-1.5 cursor-pointer select-none px-2 py-1 rounded bg-carbon-800/60 border border-carbon-700/60 hover:border-carbon-600">
            <input 
              type="checkbox" 
              checked={showParams} 
              onChange={e => setShowParams(e.target.checked)} 
              className="rounded border-carbon-600 bg-carbon-850 text-brand-400 focus:ring-0 focus:ring-offset-0"
            />
            <span className="text-carbon-300 font-medium text-[11px]">Params</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer select-none px-2 py-1 rounded bg-carbon-800/60 border border-carbon-700/60 hover:border-carbon-600">
            <input 
              type="checkbox" 
              checked={showJsFiles} 
              onChange={e => setShowJsFiles(e.target.checked)} 
              className="rounded border-carbon-600 bg-carbon-850 text-brand-400 focus:ring-0 focus:ring-offset-0"
            />
            <span className="text-carbon-300 font-medium text-[11px]">JS Files</span>
          </label>

          <label className="flex items-center gap-1.5 cursor-pointer select-none px-2 py-1 rounded bg-rose-500/10 border border-rose-500/30 hover:border-rose-500/50">
            <input 
              type="checkbox" 
              checked={showFindingsOnly} 
              onChange={e => setShowFindingsOnly(e.target.checked)} 
              className="rounded border-rose-600 bg-carbon-850 text-rose-500 focus:ring-0 focus:ring-offset-0"
            />
            <span className="text-rose-400 font-semibold text-[11px]">Findings</span>
          </label>

          {/* Inspector Toggle */}
          <button
            type="button"
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className={`px-2.5 py-1 rounded text-[11px] font-semibold flex items-center gap-1 transition ${
              isSidebarOpen 
                ? 'bg-brand-500/20 text-brand-200 border border-brand-500/40 shadow-glow-brand' 
                : 'bg-carbon-800 text-carbon-400 border border-carbon-700 hover:text-carbon-200'
            }`}
            title={isSidebarOpen ? "Close Inspector" : "Open Inspector"}
          >
            <span>🔍</span>
            <span className="hidden sm:inline">Inspector</span>
          </button>

          {/* Fullscreen Mode Toggle */}
          <button
            type="button"
            onClick={() => setIsFullscreen(!isFullscreen)}
            className="p-1 rounded text-carbon-400 hover:text-carbon-100 hover:bg-carbon-800 transition"
            title={isFullscreen ? "Exit Fullscreen" : "Fullscreen View"}
          >
            {isFullscreen ? '✕' : '⛶'}
          </button>
        </div>
      </div>

      {/* Main Graph Area */}
      <div className="flex-1 flex min-h-0 relative overflow-hidden bg-gradient-to-br from-carbon-950 via-carbon-900 to-carbon-950">
        {/* Dedicated Canvas Container with min-w-0 to prevent flex crush */}
        <div ref={containerRef} className="flex-1 min-w-0 h-full relative overflow-hidden">
          <canvas 
            ref={canvasRef}
            onMouseDown={handleMouseDown}
            onMouseMove={handleMouseMove}
            onMouseUp={handleMouseUp}
            onMouseLeave={handleMouseUp}
            onWheel={handleWheel}
            className="w-full h-full block cursor-grab active:cursor-grabbing"
          />

          {/* Top-Left Cyber Stats Floating Badge */}
          <div className="absolute top-3 left-3 flex flex-col gap-1.5 bg-carbon-950/85 backdrop-blur-md border border-carbon-700/80 rounded-xl p-3 text-xs select-none shadow-2xl">
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-indigo-500 shadow-[0_0_8px_#8b5cf6]"></span>
              <span className="text-carbon-300 font-medium text-[11px]">Target: <b className="text-carbon-100">1</b></span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-sky-400 shadow-[0_0_8px_#38bdf8]"></span>
              <span className="text-carbon-300 font-medium text-[11px]">Endpoints: <b className="text-carbon-100">{endpointCount}</b></span>
            </div>
            {showParams && (
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-amber-400 shadow-[0_0_8px_#fbbf24]"></span>
                <span className="text-carbon-300 font-medium text-[11px]">Parameters: <b className="text-carbon-100">{paramCount}</b></span>
              </div>
            )}
            <div className="flex items-center gap-2 pt-1 border-t border-carbon-800">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500 shadow-[0_0_10px_#f43f5e] animate-pulse"></span>
              <span className="text-rose-300 font-bold text-[11px]">Findings: <b>{findingCount}</b></span>
            </div>
          </div>

          {/* Bottom-Left Floating Zoom & Physics Controls */}
          <div className="absolute bottom-3 left-3 flex items-center gap-1.5 bg-carbon-950/85 backdrop-blur-md border border-carbon-700/80 rounded-lg p-1 text-xs shadow-xl">
            <button 
              type="button"
              onClick={zoomIn}
              title="Zoom In"
              className="w-7 h-7 rounded flex items-center justify-center bg-carbon-800 hover:bg-carbon-700 text-carbon-200 font-bold"
            >
              +
            </button>
            <button 
              type="button"
              onClick={zoomOut}
              title="Zoom Out"
              className="w-7 h-7 rounded flex items-center justify-center bg-carbon-800 hover:bg-carbon-700 text-carbon-200 font-bold"
            >
              −
            </button>
            <button 
              type="button"
              onClick={resetTransform}
              title="Fit / Center View"
              className="px-2.5 h-7 rounded flex items-center justify-center bg-carbon-800 hover:bg-carbon-700 text-carbon-300 text-[11px] font-medium"
            >
              ⛶ Center
            </button>
            <button 
              type="button"
              onClick={() => setIsPhysicsActive(!isPhysicsActive)}
              title={isPhysicsActive ? "Pause Physics" : "Resume Physics"}
              className={`px-2.5 h-7 rounded flex items-center justify-center text-[11px] font-medium transition-colors ${
                isPhysicsActive 
                  ? 'bg-emerald-500/15 border border-emerald-500/30 text-emerald-300' 
                  : 'bg-amber-500/15 border border-amber-500/30 text-amber-300'
              }`}
            >
              {isPhysicsActive ? '⚡ Physics Live' : '⏸️ Paused'}
            </button>
          </div>
        </div>

        {/* Node Metadata Inspector Sidebar with shrink-0 and clean padding */}
        {isSidebarOpen && (
          <div className="w-72 sm:w-80 shrink-0 bg-carbon-950/90 backdrop-blur-xl border-l border-carbon-700/80 p-4 sm:p-5 overflow-y-auto text-xs flex flex-col gap-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-carbon-800 pb-3">
              <h3 className="font-bold text-carbon-300 uppercase tracking-widest text-[10px] flex items-center gap-1.5">
                <span>🔍</span> Attack Surface Inspector
              </h3>
              <div className="flex items-center gap-2">
                {selectedNode && (
                  <button 
                    onClick={() => setSelectedNode(null)} 
                    className="text-[10px] text-carbon-400 hover:text-carbon-200"
                  >
                    Clear
                  </button>
                )}
                <button
                  type="button"
                  onClick={() => setIsSidebarOpen(false)}
                  className="text-carbon-400 hover:text-carbon-100 p-0.5"
                  title="Close Inspector"
                >
                  ✕
                </button>
              </div>
            </div>

            {selectedNode ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="text-[10px] text-carbon-500 font-bold uppercase tracking-wider">Node Type</div>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                    selectedNode.type === 'finding' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                    selectedNode.type === 'endpoint' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' :
                    selectedNode.type === 'param' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                    'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                  }`}>
                    {selectedNode.type}
                  </span>
                </div>
                
                {selectedNode.type === 'target' && (
                  <div className="space-y-2">
                    <div className="text-[10px] text-carbon-500 font-bold uppercase">Root Domain</div>
                    <div className="text-xs font-mono font-bold bg-carbon-900 border border-carbon-700/80 p-2.5 rounded-lg text-brand-300 break-all shadow-inner select-all">
                      {selectedNode.label}
                    </div>
                  </div>
                )}

                {selectedNode.type === 'endpoint' && (
                  <div className="space-y-3">
                    <div>
                      <div className="text-[10px] text-carbon-500 font-bold uppercase">HTTP Method</div>
                      <span className={`inline-block px-2.5 py-0.5 rounded text-[11px] font-mono font-bold mt-1 shadow-sm ${
                        selectedNode.method === 'POST' 
                          ? 'bg-rose-500/20 border border-rose-500/40 text-rose-300' 
                          : 'bg-sky-500/20 border border-sky-500/40 text-sky-300'
                      }`}>
                        {selectedNode.method}
                      </span>
                    </div>
                    <div>
                      <div className="text-[10px] text-carbon-500 font-bold uppercase">URL Pattern</div>
                      <div className="text-xs font-mono mt-1 bg-carbon-900 border border-carbon-700/80 p-2.5 rounded-lg text-carbon-200 break-all select-all shadow-inner">
                        {selectedNode.label}
                      </div>
                    </div>
                  </div>
                )}

                {selectedNode.type === 'param' && (
                  <div className="space-y-3">
                    <div>
                      <div className="text-[10px] text-carbon-500 font-bold uppercase">Parameter Name</div>
                      <div className="text-sm font-bold text-amber-300 mt-1 font-mono bg-carbon-900 border border-carbon-700/80 p-2 rounded-lg select-all break-all">
                        {selectedNode.name}
                      </div>
                    </div>
                    <div>
                      <div className="text-[10px] text-carbon-500 font-bold uppercase">Parameter Location</div>
                      <span className="inline-block px-2.5 py-0.5 rounded bg-carbon-800 border border-carbon-700 text-[10px] font-bold text-carbon-300 mt-1 uppercase">
                        {selectedNode.location}
                      </span>
                    </div>
                  </div>
                )}

                {selectedNode.type === 'finding' && (
                  <div className="space-y-3">
                    <div>
                      <div className="text-[10px] text-carbon-500 font-bold uppercase">Severity</div>
                      <span className="inline-block px-2.5 py-0.5 rounded bg-rose-500/20 border border-rose-500/40 text-[11px] font-bold text-rose-300 mt-1 uppercase">
                        {selectedNode.severity}
                      </span>
                    </div>
                    <div>
                      <div className="text-[10px] text-carbon-500 font-bold uppercase">Vulnerability Type</div>
                      <div className="text-xs font-bold mt-1 text-brand-300">
                        {(selectedNode.vuln_type || 'xss').replace(/_/g, ' ').toUpperCase()}
                      </div>
                    </div>
                    {selectedNode.payload && (
                      <div>
                        <div className="text-[10px] text-carbon-500 font-bold uppercase">Verified Payload</div>
                        <div className="text-xs font-mono mt-1 bg-rose-950/30 border border-rose-900/60 p-2.5 rounded-lg text-rose-200 break-all select-all font-semibold">
                          {selectedNode.payload}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-4 text-carbon-500 gap-2">
                <div className="text-2xl opacity-60">🎯</div>
                <p className="text-[11px] leading-relaxed">
                  Click or drag any node on the canvas to inspect attack surface parameters, method specs, and verified payloads.
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

export default EndpointsMap;
