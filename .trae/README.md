# .trae 目录结构说明

本目录用于存放 Trae AI 助手生成的工作文件，按照**功能/任务**维度组织：

## 目录结构

```
.trae/
├── <功能名称>/           # 每个功能或任务一个独立目录
│   ├── plan.md          # 该功能的计划文件
│   ├── spec.md          # 该功能的规格文件
│   ├── tasks.md         # 该功能的任务列表
│   ├── checklist.md     # 该功能的检查清单
│   └── analysis.md      # 该功能的分析文档
└── README.md            # 本说明文件
```

## 示例

```
.trae/
├── project-analysis/     # 项目分析任务
│   ├── plan.md
│   └── analysis.md
├── feature-snapshot/     # 快照功能开发
│   ├── plan.md
│   ├── spec.md
│   └── tasks.md
└── README.md
```

## 命名规范

- **功能目录名**: 使用英文小写，单词间用连字符连接，如 `project-analysis`, `feature-incremental-backup`
- **文件名**: 固定使用 `plan.md`, `spec.md`, `tasks.md`, `checklist.md`, `analysis.md`

## 注意事项

1. 每个功能/任务创建独立目录
2. 相关文件放在同一目录下，便于管理
3. 任务完成后可保留目录作为历史记录
