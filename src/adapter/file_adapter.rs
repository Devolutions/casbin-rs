use crate::adapter::Adapter;
use crate::errors::CasbinError;
use crate::model::Model;

use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;

use crate::Result;

pub struct FileAdapter {
    pub file_path: String,
}

type LoadPolicyFileHandler = fn(String, &mut Model);

impl FileAdapter {
    pub fn new(path: &str) -> Self {
        FileAdapter {
            file_path: path.to_owned(),
        }
    }

    pub fn load_policy_file(&self, m: &mut Model, handler: LoadPolicyFileHandler) -> Result<()> {
        let f = File::open(self.file_path.clone())?;
        let f = BufReader::new(f);
        for line in f.lines() {
            handler(line?, m);
        }
        Ok(())
    }

    pub fn save_policy_file(&self, text: String) -> Result<()> {
        let mut file = File::create(self.file_path.clone())?;
        file.write_all(text.as_bytes())?;
        Ok(())
    }
}

impl Adapter for FileAdapter {
    fn load_policy(&self, m: &mut Model) -> Result<()> {
        self.load_policy_file(m, load_policy_line)?;
        Ok(())
    }

    fn save_policy(&self, m: &mut Model) -> Result<()> {
        if self.file_path == "" {
            return Err(CasbinError::Error("save policy failed, file path is empty"));
        }

        let mut tmp = String::new();
        let ast_map1 = m.model.get("p").unwrap();
        for (ptype, ast) in ast_map1 {
            for rule in &ast.policy {
                let s1 = format!("{}, {}\n", ptype, rule.join(","));
                tmp += s1.as_str();
            }
        }

        let ast_map2 = m.model.get("g").unwrap();
        for (ptype, ast) in ast_map2 {
            for rule in &ast.policy {
                let s1 = format!("{}, {}\n", ptype, rule.join(","));
                tmp += s1.as_str();
            }
        }
        self.save_policy_file(tmp)?;
        Ok(())
    }

    fn add_policy(&mut self, _sec: &str, _ptype: &str, _rule: Vec<&str>) -> Result<bool> {
        // this api shouldn't implement, just for convinent
        Ok(true)
    }

    fn remove_policy(&self, _sec: &str, _ptype: &str, _rule: Vec<&str>) -> Result<bool> {
        // this api shouldn't implement, just for convinent
        Ok(true)
    }

    fn remove_filtered_policy(
        &self,
        _sec: &str,
        _ptype: &str,
        _field_index: usize,
        _field_values: Vec<&str>,
    ) -> Result<bool> {
        // this api shouldn't implement, just for convinent
        Ok(true)
    }
}

fn load_policy_line(line: String, m: &mut Model) {
    if line == "" || line.chars().nth(0).unwrap() == '#' {
        return;
    }
    let tokens: Vec<String> = line.split(',').map(|x| x.trim().to_string()).collect();
    let key = tokens[0].clone();
    let sec = key.chars().nth(0).unwrap().to_string();

    if let Some(t1) = m.model.get_mut(&sec) {
        if let Some(t2) = t1.get_mut(&key) {
            t2.policy.push(tokens[1..].to_vec());
            t2.policy.dedup();
        }
    }
}
