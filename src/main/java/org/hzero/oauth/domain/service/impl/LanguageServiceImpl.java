package org.hzero.oauth.domain.service.impl;

import org.hzero.oauth.domain.entity.Language;
import org.hzero.oauth.domain.service.LanguageService;
import org.hzero.oauth.infra.mapper.LanguageMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * @author qingsheng.chen@hand-china.com
 */
@Service
public class LanguageServiceImpl implements LanguageService {
    private static List<Language> languages;

    private LanguageMapper languageMapper;

    @Autowired
    public LanguageServiceImpl(LanguageMapper languageMapper) {
        this.languageMapper = languageMapper;
    }

    @Override
    public List<Language> listLanguage() {
        if (languages == null) {
            languages = languageMapper.selectAll();
        }
        return languages;
    }
}
