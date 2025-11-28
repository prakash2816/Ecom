import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import ProductCard from "@/components/ProductCard";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { authFetch, getRole, getToken, apiBase } from "@/lib/auth";
 
import type { Product } from "@/types/product";
import { ImagePlus, FileUp } from "lucide-react";
import { Trash, X, Pencil, Plus } from "lucide-react";
import { toast } from "@/components/ui/sonner";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Accordion, AccordionItem, AccordionTrigger, AccordionContent } from "@/components/ui/accordion";
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from "@/components/ui/alert-dialog";

const Admin = () => {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const role = getRole();

  useEffect(() => {
    if (role !== "admin" || !getToken()) navigate("/login");
  }, [role, navigate]);

  const { data: products = [] } = useQuery<Product[]>({
    queryKey: ["admin-products"],
    queryFn: async () => {
      const res = await authFetch("/api/products");
      return res.json();
    },
  });

  const createMutation = useMutation({
    mutationFn: async (payload: Partial<Product> & { price: number; stock?: number }) => {
      const res = await authFetch("/api/products", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!res.ok) throw new Error("Create failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["admin-products"] });
      qc.invalidateQueries({ queryKey: ["products"] });
      qc.refetchQueries({ queryKey: ["admin-products"] });
      qc.refetchQueries({ queryKey: ["products"] });
      toast("Product created successfully");
      setForm(initialForm);
      setSelectedLeninSub("");
      setThumbnailFile(null);
      setFiles([null, null, null, null, null]);
      setSelectedPreviewIndex(0);
      setFilePickerIndex(null);
      setColorItems([]);
      const thumbEl = document.getElementById("thumb-file") as HTMLInputElement | null;
      if (thumbEl) thumbEl.value = "";
      const multiEl = document.getElementById("multi-file-picker") as HTMLInputElement | null;
      if (multiEl) multiEl.value = "";
    },
  });

  

  const initialForm = { name: "", price: "", originalPrice: "", saveAmount: "", images: "", stock: "", category: "", discount: "" };
  const [form, setForm] = useState<{ name: string; price: string; originalPrice: string; saveAmount: string; images: string; stock: string; category: string; discount: string }>({
    name: "",
    price: "",
    originalPrice: "",
    saveAmount: "",
    images: "",
    stock: "",
    category: "",
    discount: "",
  });
  const [thumbnailFile, setThumbnailFile] = useState<File | null>(null);
  const [files, setFiles] = useState<(File | null)[]>([null, null, null, null, null]);
  const [filePickerIndex, setFilePickerIndex] = useState<number | null>(null);
  
  const [selectedPreviewIndex, setSelectedPreviewIndex] = useState(0);
  const [colorItems, setColorItems] = useState<{ file: File | null; imageUrl?: string; url: string }[]>([]);
  const { data: categoriesData = [] } = useQuery<string[]>({
    queryKey: ["categories"],
    queryFn: async () => {
      const res = await fetch(`${apiBase}/api/categories`);
      return res.json();
    },
  });
  const { data: subsByCat = {} as Record<string, string[]> } = useQuery<Record<string, string[]>>({
    queryKey: ["subcategories-preview"],
    queryFn: async () => {
      const cats = categoriesData || [];
      if (!cats.length) return {} as Record<string, string[]>;
      const entries = await Promise.all(cats.map(async (c) => {
        const res = await fetch(`${apiBase}/api/subcategories?category=${encodeURIComponent(c)}`);
        const arr = await res.json();
        return [c, arr] as const;
      }));
      return Object.fromEntries(entries);
    },
    enabled: (categoriesData || []).length > 0,
  });

  const topCategories = (() => {
    const allSubs = new Set(Object.values(subsByCat || {}).flat());
    return (categoriesData || []).filter((c) => !allSubs.has(c));
  })();

  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmData, setConfirmData] = useState<
    | { type: "category"; name: string }
    | { type: "sub"; category: string; name: string }
    | null
  >(null);
  const [editingCategory, setEditingCategory] = useState<string | null>(null);
  const [editingCategoryValue, setEditingCategoryValue] = useState<string>("");
  const [editingSub, setEditingSub] = useState<{ category: string; name: string } | null>(null);
  const [editingSubValue, setEditingSubValue] = useState<string>("");
  const [addingCategoryOpen, setAddingCategoryOpen] = useState(false);
  const [newCategoryName, setNewCategoryName] = useState("");
  const [addingSubFor, setAddingSubFor] = useState<string | null>(null);
  const [newSubName, setNewSubName] = useState("");
  const [openItem, setOpenItem] = useState<string | undefined>(undefined);
  const addCategoryMutation = useMutation({
    mutationFn: async (name: string) => {
      const res = await authFetch("/api/categories", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
      if (!res.ok) throw new Error("Add category failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["categories"] });
      qc.refetchQueries({ queryKey: ["categories"] });
      qc.invalidateQueries({ queryKey: ["subcategories-preview"] });
      qc.refetchQueries({ queryKey: ["subcategories-preview"] });
      toast("Category added");
      setNewCategoryName("");
      setAddingCategoryOpen(false);
    },
  });
  const delCategoryMutation = useMutation({
    mutationFn: async (name: string) => {
      const res = await authFetch(`/api/categories?name=${encodeURIComponent(name)}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Delete category failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["categories"] });
      qc.refetchQueries({ queryKey: ["categories"] });
      qc.invalidateQueries({ queryKey: ["subcategories-preview"] });
      qc.refetchQueries({ queryKey: ["subcategories-preview"] });
      toast("Category deleted");
    },
    onError: (e: unknown) => {
      const msg = e instanceof Error ? e.message : "Delete failed";
      toast(msg);
    },
  });
  const updateCategoryMutation = useMutation({
    mutationFn: async ({ oldName, newName }: { oldName: string; newName: string }) => {
      const res = await authFetch("/api/categories", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ oldName, newName }) });
      if (!res.ok) throw new Error("Update category failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["categories"] });
      qc.refetchQueries({ queryKey: ["categories"] });
      qc.invalidateQueries({ queryKey: ["subcategories-preview", categoriesData] });
      qc.refetchQueries({ queryKey: ["subcategories-preview", categoriesData] });
      toast("Category updated");
    },
  });
  const addSubMutation = useMutation({
    mutationFn: async ({ category, name }: { category: string; name: string }) => {
      const res = await authFetch("/api/subcategories", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ category, name }) });
      if (!res.ok) throw new Error("Add subcategory failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subcategories"] });
      qc.refetchQueries({ queryKey: ["subcategories"] });
      toast("Subcategory added");
      qc.invalidateQueries({ queryKey: ["subcategories-preview"] });
      qc.refetchQueries({ queryKey: ["subcategories-preview"] });
      setAddingSubFor(null);
      setNewSubName("");
    },
  });
  const updateSubMutation = useMutation({
    mutationFn: async ({ category, oldName, newName }: { category: string; oldName: string; newName: string }) => {
      const res = await authFetch("/api/subcategories", { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ category, oldName, newName }) });
      if (!res.ok) throw new Error("Update subcategory failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subcategories"] });
      qc.refetchQueries({ queryKey: ["subcategories"] });
      qc.invalidateQueries({ queryKey: ["subcategories-preview"] });
      qc.refetchQueries({ queryKey: ["subcategories-preview"] });
      toast("Subcategory updated");
    },
  });
  const delSubMutation = useMutation({
    mutationFn: async ({ category, name }: { category: string; name: string }) => {
      const res = await authFetch(`/api/subcategories?category=${encodeURIComponent(category)}&name=${encodeURIComponent(name)}`, { method: "DELETE" });
      if (!res.ok) throw new Error("Delete subcategory failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["subcategories"] });
      qc.refetchQueries({ queryKey: ["subcategories"] });
      qc.invalidateQueries({ queryKey: ["subcategories-preview"] });
      qc.refetchQueries({ queryKey: ["subcategories-preview"] });
      toast("Subcategory deleted");
    },
    onError: (e: unknown) => {
      const msg = e instanceof Error ? e.message : "Delete failed";
      toast(msg);
    },
  });
  const [selectedSub, setSelectedSub] = useState<string>("");
  const { data: formSubcats = [] } = useQuery<string[]>({
    queryKey: ["subcategories", form.category],
    queryFn: async () => {
      const cat = form.category;
      if (!cat) return [];
      const res = await fetch(`${apiBase}/api/subcategories?category=${encodeURIComponent(cat)}`);
      return res.json();
    },
    enabled: !!form.category,
  });
  const { data: banners = [] } = useQuery<string[]>({
    queryKey: ["banners"],
    queryFn: async () => {
      const res = await fetch(`${apiBase}/api/banners`);
      return res.json();
    },
  });
  const { data: carousel = [] } = useQuery<string[]>({
    queryKey: ["carousel"],
    queryFn: async () => {
      const res = await fetch(`${apiBase}/api/carousel`);
      return res.json();
    },
  });
  const saveCarouselMutation = useMutation({
    mutationFn: async (images: string[]) => {
      const res = await authFetch("/api/carousel", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ images }) });
      if (!res.ok) throw new Error("Save carousel failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["carousel"] });
      qc.refetchQueries({ queryKey: ["carousel"] });
      toast("Carousel updated");
    },
  });
  const addBannersMutation = useMutation({
    mutationFn: async (urls: string[]) => {
      const res = await authFetch("/api/banners", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ urls }),
      });
      if (!res.ok) throw new Error("Add banners failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["banners"] });
      qc.refetchQueries({ queryKey: ["banners"] });
      toast("Banner updated");
    },
  });
  const deleteBannerMutation = useMutation({
    mutationFn: async (url: string) => {
      const res = await authFetch("/api/banners", {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      if (!res.ok) throw new Error("Delete banner failed");
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["banners"] });
      qc.refetchQueries({ queryKey: ["banners"] });
    },
  });

  const [adminSearchTerm, setAdminSearchTerm] = useState("");

  function BestSellersManager({ products }: { products: Product[] }) {
    const qc = useQueryClient();
    const { data: current = [] } = useQuery<Product[]>({
      queryKey: ["bestsellers"],
      queryFn: async () => {
        const res = await authFetch("/api/bestsellers");
        return res.json();
      },
    });
    const [slotIds, setSlotIds] = useState<string[]>(["", "", "", "", ""]);
    useEffect(() => {
      const ids = current.map((p) => p.id);
      setSlotIds((["", "", "", "", ""]).map((_, i) => ids[i] || ""));
    }, [current]);
    const saveListMutation = useMutation({
      mutationFn: async (ids: string[]) => {
        const res = await authFetch("/api/bestsellers", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ ids }),
        });
        if (!res.ok) throw new Error("Save failed");
        return res.json();
      },
      onSuccess: () => {
        qc.invalidateQueries({ queryKey: ["bestsellers"] });
        qc.refetchQueries({ queryKey: ["bestsellers"] });
        toast("Bestsellers updated");
      },
    });
    const delMutation = useMutation({
      mutationFn: async (id: string) => {
        const res = await authFetch(`/api/bestsellers/${id}`, { method: "DELETE" });
        if (!res.ok) throw new Error("Delete failed");
        return res.json();
      },
      onSuccess: () => {
        qc.invalidateQueries({ queryKey: ["bestsellers"] });
        qc.refetchQueries({ queryKey: ["bestsellers"] });
      },
    });
    return (
      <div className="space-y-4">
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
          {[0,1,2,3,4].map((idx) => {
            const pid = slotIds[idx] || "";
            const p = pid ? current.find((x) => x.id === pid) : undefined;
            return (
              <div key={`slot-${idx}`}>
                <div className="flex gap-2 items-center mb-2">
                  <select
                    className="border rounded-md px-2 py-1 bg-background w-full"
                    value={pid}
                    onChange={(e) => setSlotIds((ids) => { const ni = [...ids]; ni[idx] = e.target.value; return ni; })}
                  >
                    <option value="">Select product</option>
                    {products.map((pp) => (
                      <option key={pp.id} value={pp.id}>{pp.name}</option>
                    ))}
                  </select>
                  <Button
                    onClick={() => {
                      const arr = slotIds.map((x) => x).filter(Boolean);
                      saveListMutation.mutate(arr);
                    }}
                    disabled={!slotIds[idx]}
                  >Add</Button>
                </div>
                {p ? (
                  <>
                    <ProductCard product={p} compact />
                    <div className="mt-2 flex justify-end">
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => {
                          setSlotIds((ids) => { const ni = [...ids]; ni[idx] = ""; return ni; });
                          const arr = slotIds.map((x, i) => (i === idx ? "" : x)).filter(Boolean);
                          saveListMutation.mutate(arr);
                        }}
                      >Remove</Button>
                    </div>
                  </>
                ) : (
                  <div className="relative overflow-hidden rounded-lg bg-card aspect-[3/4] border-2 border-dashed flex items-center justify-center">
                    <button
                      type="button"
                      className="h-12 w-12 rounded-full border bg-background flex items-center justify-center"
                      onClick={() => slotIds[idx] && saveListMutation.mutate(slotIds.filter(Boolean))}
                      disabled={!slotIds[idx]}
                    >
                      <Plus className="h-6 w-6" />
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    );
  }

  function CategoryTilesManager({ categories }: { categories: string[] }) {
    const qc = useQueryClient();
    type CategoryTile = { category: string; image: string; position: number };
    const { data: tiles = [] } = useQuery<CategoryTile[]>({
      queryKey: ["category-tiles"],
      queryFn: async () => {
        const res = await authFetch("/api/category-tiles");
        return res.json();
      },
    });
    const [files, setFiles] = useState<(File | null)[]>([null, null, null, null, null, null]);
    const [values, setValues] = useState<string[]>(["", "", "", "", "", ""]);
    const addMutation = useMutation({
      mutationFn: async (pos: number) => {
        const category = values[pos];
        const file = files[pos];
        if (!category || !file) throw new Error("Select category and image");
        const fd = new FormData();
        fd.append("files", file);
        const upRes = await authFetch("/api/upload", { method: "POST", body: fd });
        if (!upRes.ok) throw new Error("Upload failed");
        const up = await upRes.json();
        const image = (up.urls || [])[0];
        const res = await authFetch("/api/category-tiles", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ category, image, position: pos }),
        });
        if (!res.ok) throw new Error("Save failed");
        return res.json();
      },
      onSuccess: (_data, pos) => {
        qc.setQueryData<CategoryTile[]>(["category-tiles"], (old) => {
          const arr: CategoryTile[] = Array.isArray(old) ? [...old] : [];
          const idx = arr.findIndex((t) => Number(t.position) === Number(pos));
          const category = values[pos];
          if (idx >= 0) arr[idx] = { position: pos, category, image: "" };
          else arr.push({ position: pos, category, image: "" });
          return arr;
        });
        qc.invalidateQueries({ queryKey: ["category-tiles"] });
        qc.refetchQueries({ queryKey: ["category-tiles"] });
        toast("Category tile updated");
        setFiles((fs) => { const nf = [...fs]; nf[pos] = null; return nf; });
      },
    });
    const delMutation = useMutation({
      mutationFn: async (position: number) => {
        const res = await authFetch(`/api/category-tiles?position=${position}`, { method: "DELETE" });
        if (!res.ok) throw new Error("Delete failed");
        return res.json();
      },
      onSuccess: (_data, position) => {
        qc.setQueryData<CategoryTile[]>(["category-tiles"], (old) => {
          const arr: CategoryTile[] = Array.isArray(old) ? [...old] : [];
          return arr.filter((t) => Number(t.position) !== Number(position));
        });
        qc.invalidateQueries({ queryKey: ["category-tiles"] });
        qc.refetchQueries({ queryKey: ["category-tiles"] });
      },
    });
    const tileByPos: Record<number, { category: string; image: string } | undefined> = {};
    for (const t of tiles) tileByPos[t.position] = { category: t.category, image: t.image };
    return (
      <div className="space-y-6">
        {[0,1,2,3,4,5].map((pos) => (
          <div key={pos} className="flex items-center gap-3">
            <select
              className="border rounded-md px-2 py-1 bg-background"
              value={values[pos]}
              onChange={(e) => setValues((v) => { const nv = [...v]; nv[pos] = e.target.value; return nv; })}
            >
              <option value="">Select category</option>
              {categories.map((c) => (
                <option key={c} value={c}>{c}</option>
              ))}
            </select>
            <input type="file" accept="image/*" onChange={(e) => setFiles((fs) => { const nf = [...fs]; nf[pos] = e.target.files?.[0] || null; return nf; })} />
            <Button onClick={() => addMutation.mutate(pos)} disabled={!values[pos] || !files[pos]}>Add</Button>
            {tileByPos[pos] && (
              <div className="flex items-center gap-2">
                <img src={tileByPos[pos]!.image || "/placeholder.svg"} alt={tileByPos[pos]!.category} className="w-16 h-16 rounded object-cover" />
                <span className="text-sm">{tileByPos[pos]!.category}</span>
                <Button variant="destructive" size="sm" onClick={() => delMutation.mutate(pos)}>Remove</Button>
              </div>
            )}
          </div>
        ))}
      </div>
    );
  }

  function CarouselItemEditor({ index, currentUrl, onSave, onRemove }: { index: number; currentUrl?: string; onSave: (file: File | null) => void; onRemove: () => void }) {
    const [file, setFile] = useState<File | null>(null);
    return (
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="relative w-24 h-16 rounded-md overflow-hidden border bg-card flex items-center justify-center"
            onClick={() => (document.getElementById(`carousel-file-${index}`) as HTMLInputElement | null)?.click()}
          >
            {file ? (
              <img src={URL.createObjectURL(file)} alt="carousel" className="w-full h-full object-cover" />
            ) : currentUrl ? (
              <img src={currentUrl} alt="carousel" className="w-full h-full object-cover" />
            ) : (
              <ImagePlus className="h-6 w-6 text-muted-foreground" />
            )}
          </button>
          <input id={`carousel-file-${index}`} type="file" accept="image/*" className="hidden" onChange={(e) => setFile(e.target.files?.[0] || null)} />
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" onClick={() => onSave(file)} disabled={!file}>Save</Button>
          <Button variant="destructive" onClick={onRemove} disabled={!currentUrl}>Remove</Button>
        </div>
      </div>
    );
  }

  function ColorOptionsEditor() {
    return (
      <div className="space-y-3">
        {colorItems.map((ci, idx) => (
          <div key={`color-${idx}`} className="space-y-2">
            <button
              type="button"
              className="relative w-16 h-16 rounded-md overflow-hidden border bg-card flex items-center justify-center"
              onClick={() => {
                const el = document.getElementById(`color-file-${idx}`) as HTMLInputElement | null;
                el?.click();
              }}
            >
              {ci.file || ci.imageUrl ? (
                <>
                  <img src={ci.file ? URL.createObjectURL(ci.file) : (ci.imageUrl || "/placeholder.svg")} alt="color" className="w-full h-full object-cover" />
                  <button
                    type="button"
                    className="absolute top-1 right-1 bg-background/70 rounded-md p-1"
                    onClick={(e) => { e.stopPropagation(); setColorItems((items) => items.map((it, i) => i === idx ? { ...it, file: null, imageUrl: undefined } : it)); }}
                    aria-label="Remove"
                  >
                    <X className="h-3 w-3" />
                  </button>
                </>
              ) : (
                <ImagePlus className="h-6 w-6 text-muted-foreground" />
              )}
            </button>
            <input id={`color-file-${idx}`} type="file" accept="image/*" className="hidden" onChange={(e) => {
              const f = e.target.files?.[0] || null;
              setColorItems((items) => items.map((it, i) => i === idx ? { ...it, file: f, imageUrl: undefined } : it));
            }} />
            <Input
              placeholder="Target URL"
              value={ci.url}
              onChange={(e) => setColorItems((items) => items.map((it, i) => i === idx ? { ...it, url: e.target.value } : it))}
            />
            <div>
              <Button variant="destructive" size="sm" onClick={() => setColorItems((items) => items.filter((_, i) => i !== idx))}>Remove</Button>
            </div>
          </div>
        ))}
        <div className="flex gap-2">
          <Button variant="secondary" onClick={() => setColorItems((items) => [...items, { file: null, url: "" }])}>Add Color</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="container px-4 py-8">
      <div className="flex items-center justify-between mb-6">
        <h1 className="font-serif text-3xl md:text-4xl font-bold">Admin Panel</h1>
        <div className="flex items-center gap-2">
          <Input
            value={adminSearchTerm}
            onChange={(e) => setAdminSearchTerm(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") navigate(`/admin/products?query=${encodeURIComponent(adminSearchTerm)}`);
            }}
            placeholder="Search products"
            className="w-[260px]"
          />
          <Button onClick={() => navigate(`/admin/products?query=${encodeURIComponent(adminSearchTerm)}`)}>Search</Button>
          <Button variant="outline" onClick={() => navigate("/admin/products")}>Manage Products</Button>
        </div>
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="bg-card rounded-lg p-4 space-y-4">
          <h2 className="font-serif text-2xl font-bold">Add Product</h2>
          <div>
            <Label>Name</Label>
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div>
              <Label>Price</Label>
              <Input type="number" value={form.price} onChange={(e) => setForm({ ...form, price: e.target.value })} />
            </div>
            <div>
              <Label>Discount (%)</Label>
              <Input type="number" value={form.discount} onChange={(e) => setForm({ ...form, discount: e.target.value })} />
            </div>
            <div>
              <Label>Cutoff</Label>
              <Input type="number" value={form.originalPrice} onChange={(e) => setForm({ ...form, originalPrice: e.target.value })} />
            </div>
            <div>
              <Label>Save Amount</Label>
              <Input type="number" value={form.saveAmount} onChange={(e) => setForm({ ...form, saveAmount: e.target.value })} />
            </div>
          </div>
          <div className="flex items-center gap-3">
            {form.originalPrice && (
              <span className="text-muted-foreground line-through">₹{Number(form.originalPrice).toLocaleString()}</span>
            )}
            {form.saveAmount && (
              <Badge variant="secondary">Save ₹{Number(form.saveAmount).toLocaleString()}</Badge>
            )}
          </div>
          <div>
            <Label>Main Image</Label>
            <div className="flex items-center gap-2">
              <button
                type="button"
                className="relative w-16 h-16 rounded-md overflow-hidden border bg-card flex items-center justify-center"
                onClick={() => {
                  const el = document.getElementById("thumb-file") as HTMLInputElement | null;
                  el?.click();
                }}
              >
                {thumbnailFile ? (
                  <>
                    <img src={URL.createObjectURL(thumbnailFile)} alt="main" className="w-full h-full object-cover" />
                    <button
                      type="button"
                      className="absolute top-1 right-1 bg-background/70 rounded-md p-1"
                      onClick={(e) => { e.stopPropagation(); setThumbnailFile(null); }}
                      aria-label="Remove"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </>
                ) : (
                  <ImagePlus className="h-6 w-6 text-muted-foreground" />
                )}
              </button>
              <input
                id="thumb-file"
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0] || null;
                  setThumbnailFile(f);
                }}
              />
            </div>
          </div>
          <div>
            <Label>Upload Images</Label>
            <div className="grid grid-cols-5 gap-2">
              {[0,1,2,3,4].map((i) => (
                <button
                  key={i}
                  type="button"
                  className="relative w-16 h-16 rounded-md overflow-hidden border bg-card flex items-center justify-center"
                  onClick={() => {
                    setFilePickerIndex(i);
                    const el = document.getElementById("multi-file-picker") as HTMLInputElement | null;
                    el?.click();
                  }}
                >
                  {files[i] ? (
                    <>
                      <img src={URL.createObjectURL(files[i]!)} alt="img" className="w-full h-full object-cover" />
                      <button
                        type="button"
                        className="absolute top-1 right-1 bg-background/70 rounded-md p-1"
                        onClick={(e) => { e.stopPropagation(); const next = [...files]; next[i] = null; setFiles(next); }}
                        aria-label="Remove"
                      >
                        <X className="h-3 w-3" />
                      </button>
                    </>
                  ) : (
                    <ImagePlus className="h-6 w-6 text-muted-foreground" />
                  )}
                </button>
              ))}
              <input
                id="multi-file-picker"
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0] || null;
                  if (filePickerIndex === null) return;
                  const next = [...files];
                  next[filePickerIndex] = f;
                  setFiles(next);
                  setFilePickerIndex(null);
                }}
              />
            </div>
          </div>
          <div className="space-y-3">
            <Label>Color</Label>
            <ColorOptionsEditor />
          </div>
          <div>
            <Label>Stock</Label>
            <Input type="number" value={form.stock} onChange={(e) => setForm({ ...form, stock: e.target.value })} />
          </div>
          <div>
            <Label>Category</Label>
            <div className="space-y-2">
              <Select value={form.category} onValueChange={(v) => {
                setForm({ ...form, category: v });
                setSelectedSub("");
              }}>
                <SelectTrigger>
                  <SelectValue placeholder="Select category" />
                </SelectTrigger>
                <SelectContent>
                  {topCategories.map((c) => (
                    <SelectItem key={c} value={c}>{c}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {form.category && formSubcats.length > 0 && (
                <div>
                  <Label>Subcategory</Label>
                  <Select value={selectedSub} onValueChange={setSelectedSub}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select subcategory" />
                    </SelectTrigger>
                    <SelectContent>
                      {formSubcats.map((s) => (
                        <SelectItem key={s} value={s}>{s}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>
          </div>
          <Button
            onClick={async () => {
              let thumbUrl: string | null = null;
              if (thumbnailFile) {
                const tfd = new FormData();
                tfd.append("files", thumbnailFile);
                const tres = await authFetch("/api/upload", { method: "POST", body: tfd });
                const tdata = await tres.json();
                thumbUrl = (tdata.urls || [])[0] || null;
              }
              let uploaded: string[] = [];
              const selected = files.filter(Boolean) as File[];
              if (selected.length) {
                const fd = new FormData();
                selected.forEach((f) => fd.append("files", f));
                const res = await authFetch("/api/upload", { method: "POST", body: fd });
                const data = await res.json();
                uploaded = data.urls || [];
              }
              const thumbInputUrl = form.images.trim();
              const firstImage = thumbUrl || (thumbInputUrl ? thumbInputUrl : undefined);
              const urls = [] as string[];
              const imagesArray = firstImage ? [firstImage, ...uploaded, ...urls] : [...uploaded, ...urls];
              // prepare colorLinks from editor state
              const colorLinks = colorItems
                .map((ci) => ({ image: ci.imageUrl || "", file: ci.file, url: ci.url }))
                .filter((ci) => ci.file || ci.imageUrl);
              const filesToUpload = colorLinks.filter((ci) => ci.file).map((ci) => ci.file!)
              let uploadedColorUrls: string[] = [];
              if (filesToUpload.length) {
                const cfd = new FormData();
                filesToUpload.forEach((f) => cfd.append("files", f));
                const cres = await authFetch("/api/upload", { method: "POST", body: cfd });
                const cdata = await cres.json();
                uploadedColorUrls = cdata.urls || [];
              }
              let colorUrlIndex = 0;
              const finalColorLinks = colorLinks.map((ci) => ({
                image: ci.file ? uploadedColorUrls[colorUrlIndex++] : (ci.imageUrl || ""),
                url: ci.url,
              })).filter((x) => x.image && x.url);

              await createMutation.mutateAsync({
                name: form.name,
                price: Number(form.price),
                images: imagesArray,
                stock: Number(form.stock || 0),
                category: selectedSub || form.category,
                originalPrice: form.originalPrice ? Number(form.originalPrice) : undefined,
                saveAmount: form.saveAmount ? Number(form.saveAmount) : undefined,
                discount: form.discount ? Number(form.discount) : undefined,
                colorLinks: finalColorLinks,
              });
              setForm(initialForm);
              setSelectedSub("");
              setThumbnailFile(null);
              setFiles([null, null, null, null, null]);
              setSelectedPreviewIndex(0);
              setFilePickerIndex(null);
              setColorItems([]);
              const thumbEl = document.getElementById("thumb-file") as HTMLInputElement | null;
              if (thumbEl) thumbEl.value = "";
              const multiEl = document.getElementById("multi-file-picker") as HTMLInputElement | null;
              if (multiEl) multiEl.value = "";
            }}
          >
            Create
          </Button>
        </div>

        <div className="bg-card rounded-lg p-4 space-y-4">
          <h2 className="font-serif text-2xl font-bold">Product Preview</h2>
          {form.name && (
            <div className="space-y-3">
              {(() => {
                const sources = [
                  thumbnailFile ? URL.createObjectURL(thumbnailFile) : (form.images.trim() || ""),
                  ...files.map((f) => (f ? URL.createObjectURL(f) : "")),
                ].filter(Boolean);
                const current = sources[selectedPreviewIndex] || sources[0] || "/placeholder.svg";
                return (
                  <>
                    <div className="relative overflow-hidden rounded-lg bg-card aspect-[3/4] max-w-[400px] mb-3">
                      <img src={current} alt={form.name} className="h-full w-full object-cover" />
                      {form.discount && (
                        <Badge className="absolute top-3 left-3 bg-primary text-primary-foreground">
                          {form.discount}% OFF
                        </Badge>
                      )}
                    </div>
                    {sources.length > 1 && (
                      <div className="flex gap-2 overflow-x-auto pb-1">
                        {sources.map((src, index) => (
                          <button
                            key={index}
                            onClick={() => setSelectedPreviewIndex(index)}
                            className={`flex-shrink-0 w-16 h-16 rounded-md overflow-hidden border-2 ${
                              selectedPreviewIndex === index ? "border-primary" : "border-transparent"
                            }`}
                          >
                            <img src={src} alt={`preview ${index + 1}`} className="w-full h-full object-cover" />
                          </button>
                        ))}
                      </div>
                    )}
                  </>
                );
              })()}
              <h3 className="font-serif text-lg font-medium">{form.name}</h3>
              <div className="flex items-center gap-2">
                <span className="text-lg font-semibold">₹{form.price}</span>
              </div>
            </div>
          )}
        </div>

        
        <div className="md:col-span-2 bg-card rounded-lg p-6 space-y-4">
          <h2 className="font-serif text-2xl font-bold">Carousel Images</h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
            {[0,1,2,3,4].map((idx) => (
              <CarouselItemEditor
                key={idx}
                index={idx}
                currentUrl={carousel[idx] || ""}
                onSave={async (file) => {
                  if (!file) return;
                  const fd = new FormData();
                  fd.append("files", file);
                  const res = await authFetch("/api/upload", { method: "POST", body: fd });
                  const data = await res.json();
                  const url = (data.urls || [])[0];
                  const next = [...carousel];
                  next[idx] = url;
                  saveCarouselMutation.mutate(next);
                }}
                onRemove={() => {
                  const next = [...carousel];
                  next[idx] = "";
                  saveCarouselMutation.mutate(next.filter(Boolean));
                }}
              />
            ))}
          </div>
        </div>

        <div className="md:col-span-2 bg-card rounded-lg p-6 space-y-4">
          <h2 className="font-serif text-2xl font-bold">Banner Container</h2>
          <div className="flex gap-2 items-center">
            <input
              id="banner-file"
              type="file"
              accept="image/*"
              multiple
              className="hidden"
              onChange={async (e) => {
                const list = Array.from(e.target.files || []);
                if (!list.length) return;
                const fd = new FormData();
                list.forEach((f) => fd.append("files", f));
                const res = await authFetch("/api/upload", { method: "POST", body: fd });
                const data = await res.json();
                const urls = data.urls || [];
                if (urls.length) addBannersMutation.mutate(urls);
                const bannerEl = document.getElementById("banner-file") as HTMLInputElement | null;
                if (bannerEl) bannerEl.value = "";
              }}
            />
            <Button variant="secondary" onClick={() => (document.getElementById("banner-file") as HTMLInputElement | null)?.click()}>Upload Images</Button>
          </div>
          {banners.length > 0 && (
            <div className="rounded-lg overflow-hidden border bg-card">
              <img src={banners[0]} alt="Banner" className="w-full h-[260px] md:h-[320px] object-cover" />
            </div>
          )}
          {banners.length > 1 && (
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              {banners.slice(1).map((u) => (
                <div key={u} className="rounded-lg overflow-hidden border relative">
                  <img src={u} alt="banner" className="w-full h-24 object-cover" />
                  <div className="absolute bottom-2 right-2">
                    <Button variant="destructive" size="sm" onClick={() => deleteBannerMutation.mutate(u)}>Delete</Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
        <div className="md:col-span-2 bg-card rounded-lg p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="font-serif text-2xl font-bold">Categories</h2>
            <button
              type="button"
              className="text-primary hover:underline"
              onClick={() => setAddingCategoryOpen((v) => !v)}
              aria-label="Add category"
            >
              <Plus className="h-5 w-5" />
            </button>
          </div>
          {addingCategoryOpen && (
            <div className="flex gap-2">
              <Input placeholder="Category name" value={newCategoryName} onChange={(e) => setNewCategoryName(e.target.value)} />
              <Button
                variant="secondary"
                onClick={() => {
                  const name = newCategoryName.trim();
                  if (!name) return;
                  addCategoryMutation.mutate(name);
                }}
              >Add</Button>
            </div>
          )}
          <div className="h-[600px] overflow-y-auto rounded-md border w-full">
            <Accordion type="single" collapsible className="w-full" value={openItem} onValueChange={setOpenItem}>
              {topCategories.map((c) => (
                <AccordionItem key={c} value={c}>
                  <AccordionTrigger className="px-3 pr-16">
                    <div className="flex w-full items-center justify-between">
                      {editingCategory === c ? (
                        <div className="flex items-center gap-2">
                          <Input value={editingCategoryValue} onChange={(e) => setEditingCategoryValue(e.target.value)} className="h-8 w-48" />
                          <Button
                            size="sm"
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              const v = editingCategoryValue.trim();
                              if (!v || v === c) { setEditingCategory(null); return; }
                              updateCategoryMutation.mutate({ oldName: c, newName: v });
                              setEditingCategory(null);
                            }}
                          >Save</Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={(e) => { e.preventDefault(); e.stopPropagation(); setEditingCategory(null); }}
                          >Cancel</Button>
                        </div>
                      ) : (
                        <span>{c}</span>
                      )}
                      <div className="flex items-center">
                        <button
                          type="button"
                          className="ml-4 mr-2 text-muted-foreground hover:text-foreground"
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setEditingCategory(c);
                            setEditingCategoryValue(c);
                          }}
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                        <button
                          type="button"
                          className="ml-2 mr-2 text-primary hover:underline"
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setAddingSubFor(c);
                            setOpenItem(c);
                            setTimeout(() => {
                              const el = document.getElementById(`new-sub-input-${c}`) as HTMLInputElement | null;
                              el?.focus();
                            }, 0);
                          }}
                          aria-label="Add subcategory"
                        >
                          <Plus className="h-4 w-4" />
                        </button>
                        <button
                          type="button"
                          className="ml-2 mr-4 text-destructive hover:underline"
                          onClick={(e) => {
                            e.preventDefault();
                            e.stopPropagation();
                            setConfirmData({ type: "category", name: c });
                            setConfirmOpen(true);
                          }}
                        >
                          <Trash className="h-4 w-4" />
                        </button>
                      </div>
                    </div>
                  </AccordionTrigger>
                  <AccordionContent className="px-3">
                    {addingSubFor === c && (
                      <div className="flex gap-2 mb-2">
                        <Input id={`new-sub-input-${c}`} placeholder="New subcategory" value={newSubName} onChange={(e) => setNewSubName(e.target.value)} className="h-8" />
                        <Button
                          size="sm"
                          variant="secondary"
                          onClick={() => {
                            const name = newSubName.trim();
                            if (!name) return;
                            addSubMutation.mutate({ category: c, name });
                          }}
                        >Add</Button>
                        <Button size="sm" variant="ghost" onClick={() => { setAddingSubFor(null); setNewSubName(""); }}>Cancel</Button>
                      </div>
                    )}
                    <div className="flex flex-wrap gap-2">
                      {(subsByCat[c] || []).map((s) => (
                        <span key={s} className="text-xs rounded-md border px-2 py-1 flex items-center gap-1">
                          {editingSub && editingSub.category === c && editingSub.name === s ? (
                            <>
                              <Input value={editingSubValue} onChange={(e) => setEditingSubValue(e.target.value)} className="h-7 w-40 text-xs" />
                              <Button
                                size="sm"
                                className="h-7 px-2"
                                onClick={() => {
                                  const v = editingSubValue.trim();
                                  if (!v || v === s) { setEditingSub(null); return; }
                                  updateSubMutation.mutate({ category: c, oldName: s, newName: v });
                                  setEditingSub(null);
                                }}
                              >Save</Button>
                              <Button size="sm" variant="ghost" className="h-7 px-2" onClick={() => setEditingSub(null)}>Cancel</Button>
                            </>
                          ) : (
                            <>
                              <span>{s}</span>
                              <button
                                type="button"
                                className="ml-1 text-muted-foreground hover:text-foreground"
                                onClick={() => { setEditingSub({ category: c, name: s }); setEditingSubValue(s); }}
                              >
                                <Pencil className="h-3 w-3" />
                              </button>
                              <button
                                type="button"
                                className="ml-1 text-muted-foreground hover:text-destructive"
                                onClick={() => {
                                  setConfirmData({ type: "sub", category: c, name: s });
                                  setConfirmOpen(true);
                                }}
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </>
                          )}
                        </span>
                      ))}
                    </div>
                  </AccordionContent>
                </AccordionItem>
              ))}
            </Accordion>
          </div>
        </div>
        
      <div className="md:col-span-2 bg-card rounded-lg p-6 space-y-4">
        <h2 className="font-serif text-2xl font-bold">Best Sellers</h2>
        <BestSellersManager products={products} />
      </div>
      <div className="md:col-span-2 bg-card rounded-lg p-6 space-y-4">
        <h2 className="font-serif text-2xl font-bold">Category Tiles</h2>
        <CategoryTilesManager categories={topCategories} />
      </div>
      </div>
      <AlertDialog open={confirmOpen} onOpenChange={setConfirmOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {confirmData
                ? `Delete ${confirmData.type === "category" ? "category" : "subcategory"} "${confirmData.name}"?`
                : ""}
            </AlertDialogTitle>
          </AlertDialogHeader>
          <p className="text-sm text-muted-foreground">
            Are you sure you want to delete? Deleting this will remove {confirmData?.type === "category" ? "this category and all its subcategories" : "this subcategory"}.
          </p>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => {
                if (!confirmData) return;
                if (confirmData.type === "category") {
                  delCategoryMutation.mutate(confirmData.name);
                } else {
                  delSubMutation.mutate({ category: confirmData.category, name: confirmData.name });
                }
                setConfirmOpen(false);
                setConfirmData(null);
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
};

export default Admin;