# Python 调用示例

通过 Python 调用 WinKit 高级 API（RunPE、BOF、Reflective DLL 等）。

## 运行

```bash
python runpe_test.py ../gogo.exe
```

要求：Python 3.7+

## 自定义

传递参数：
```python
args = "--help"
# 在调用中传递 args
```

使用封装类：
```python
kit = MaleficWinKit("malefic_win_kit.dll")
output = kit.run_pe(sacrifice, pe_data, args="--help")
```

**详细说明见代码注释。**
