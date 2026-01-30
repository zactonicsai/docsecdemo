/**
 * Search API Routes
 * 
 * Provides full-text search capabilities with cell-level access control.
 * Search results are automatically filtered based on user permissions.
 */

const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const searchService = require('../search-service');

/**
 * GET /api/search/health
 * Check if OpenSearch is available
 */
router.get('/health', async (req, res) => {
  try {
    const available = await searchService.isAvailable();
    const stats = available ? await searchService.getSearchStats() : null;
    
    res.json({
      status: available ? 'healthy' : 'unavailable',
      opensearch: available,
      stats: stats
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error',
      error: error.message 
    });
  }
});

/**
 * POST /api/search
 * Full-text search with cell-level filtering
 * 
 * Body: {
 *   query: "search terms",
 *   user_id: "user-uuid" (for filtering),
 *   fields: ["title", "content", ...],
 *   filters: { department, classification, type, tags },
 *   from: 0,
 *   size: 10,
 *   highlight: true
 * }
 */
router.post('/', async (req, res) => {
  try {
    const { 
      query, 
      user_id,
      fields,
      filters,
      from,
      size,
      highlight 
    } = req.body;

    if (!query) {
      return res.status(400).json({ error: 'query is required' });
    }

    if (!user_id) {
      return res.status(400).json({ error: 'user_id is required for cell-level filtering' });
    }

    const results = await searchService.search(query, user_id, {
      fields,
      filters,
      from,
      size,
      highlight
    });

    res.json({
      query: query,
      ...results,
      message: results.filtered_fields.length > 0 
        ? `Some fields were filtered based on your access level: ${results.filtered_fields.join(', ')}`
        : undefined
    });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/search/aggregations
 * Search with aggregations (faceted search)
 */
router.post('/aggregations', async (req, res) => {
  try {
    const { query, user_id, size } = req.body;

    if (!user_id) {
      return res.status(400).json({ error: 'user_id is required' });
    }

    const results = await searchService.searchWithAggregations(query, user_id, { size });

    res.json(results);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/search/documents/:id
 * Get a single document with cell-level filtering
 */
router.get('/documents/:id', async (req, res) => {
  try {
    const userId = req.query.user_id;

    if (!userId) {
      return res.status(400).json({ error: 'user_id query parameter is required' });
    }

    const doc = await searchService.getDocument(req.params.id, userId);

    if (!doc) {
      return res.status(404).json({ error: 'Document not found' });
    }

    res.json(doc);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/search/documents
 * Index a new document
 */
router.post('/documents', async (req, res) => {
  try {
    const doc = {
      id: req.body.id || uuidv4(),
      ...req.body
    };

    const indexed = await searchService.indexDocument(doc);

    res.status(201).json({
      message: 'Document indexed successfully',
      document: indexed
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/search/documents/bulk
 * Bulk index documents
 */
router.post('/documents/bulk', async (req, res) => {
  try {
    const { documents } = req.body;

    if (!documents || !Array.isArray(documents)) {
      return res.status(400).json({ error: 'documents array is required' });
    }

    // Assign IDs if not present
    const docsWithIds = documents.map(doc => ({
      id: doc.id || uuidv4(),
      ...doc
    }));

    const result = await searchService.bulkIndexDocuments(docsWithIds);

    res.status(201).json({
      message: `Indexed ${result.indexed} documents`,
      ...result
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * PUT /api/search/documents/:id
 * Update/reindex a document
 */
router.put('/documents/:id', async (req, res) => {
  try {
    const doc = {
      id: req.params.id,
      ...req.body
    };

    const indexed = await searchService.indexDocument(doc);

    res.json({
      message: 'Document updated successfully',
      document: indexed
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * DELETE /api/search/documents/:id
 * Delete a document from the index
 */
router.delete('/documents/:id', async (req, res) => {
  try {
    const deleted = await searchService.deleteDocument(req.params.id);

    if (!deleted) {
      return res.status(404).json({ error: 'Document not found' });
    }

    res.json({ 
      message: 'Document deleted successfully',
      id: req.params.id
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /api/search/stats
 * Get search index statistics
 */
router.get('/stats', async (req, res) => {
  try {
    const stats = await searchService.getSearchStats();
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
