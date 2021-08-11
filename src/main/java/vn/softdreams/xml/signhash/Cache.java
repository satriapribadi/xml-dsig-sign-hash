package vn.softdreams.xml.signhash;

import com.google.common.cache.CacheBuilder;
import org.w3c.dom.Document;

import java.util.concurrent.TimeUnit;

public class Cache {
    private static Cache instance = null;

    private final long MAX_RECORDS = 1000;
    private final int TIME_OUT_IN_SECONDS = 30;
    private final int DEFAULT_CONCURRENCY_LEVEL = 4;
    private com.google.common.cache.Cache<String, Document> cache = null;

    public static Cache getInstance() {
        if (instance == null) {
            instance = new Cache();
        }
        return instance;
    }

    private Cache() {
        cache = CacheBuilder.newBuilder()
                .maximumSize(MAX_RECORDS)
                .expireAfterWrite(TIME_OUT_IN_SECONDS, TimeUnit.SECONDS)
                .concurrencyLevel(DEFAULT_CONCURRENCY_LEVEL)
                .recordStats()
                .build();
    }

    public void set(String key, Document value) {
        cache.put(key, value);
    }

    public Document get(String key) {
        return cache.getIfPresent(key);
    }

    public boolean contain(String key) {
        return cache.getIfPresent(key) != null;
    }

    public void remove(String key) {
        if (contain(key))
            cache.invalidate(key);
    }

    public boolean isFull() {
        return cache.size() == MAX_RECORDS;
    }
}
